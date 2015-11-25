from gummanager.libs.utils import configure_ini
from gummanager.libs.utils import parse_ini_from
from gummanager.libs.utils import circus_status
from gummanager.libs.ports import CIRCUS_HTTPD_BASE_PORT
from gummanager.libs.ports import CIRCUS_TCP_BASE_PORT
from gummanager.libs.ports import GENWEB_ZOPE_CLIENT_BASE_PORT
from gummanager.libs.ports import MAX_BASE_PORT
from gummanager.libs.config_files import LDAP_INI
from gummanager.libs.config_files import INIT_D_SCRIPT
from gummanager.libs.config_files import MAX_NGINX_ENTRY
from gummanager.libs.utils import padded_error, step_log, success_log, error_log

from StringIO import StringIO
from collections import OrderedDict
from pyquery import PyQuery
import requests
import re


class Plone(object):
    def __init__(self, environment, mountpoint, plonesite, title="", language="", logecho=None):
        self.environment = environment
        self.mountpoint = mountpoint
        self.plonesite = plonesite
        self.title = title
        self.language = language
        self.echo = logecho

    @property
    def auth(self):
        return (self.environment['admin_username'], self.environment['admin_password'])

    @property
    def mountpoint_url(self):
        return 'http://{}:{}/{}'.format(
            self.environment['server'],
            GENWEB_ZOPE_CLIENT_BASE_PORT + 1,
            self.mountpoint
        )

    @property
    def site_url(self):
        return '{}/{}'.format(
            self.mountpoint_url,
            self.plonesite
        )

    def exists(self):
        return requests.get(self.site_url).status_code != 404

    def create(self, packages=[]):
        if self.exists():
            return error_log('There is already a ulearn on {}'.format(self.site_url))

        params = {
            "site_id": self.plonesite,
            "title": self.title,
            "default_language": self.language,
            "setup_content:boolean": True,
            "extension_ids:list": [
                'plonetheme.classic:default',
                'plonetheme.sunburst:default',
            ] + packages,
            "form.submitted:boolean": True,
            "submit": "Crear lloc Plone"
        }
        create_plone_url = '{}/@@plone-addsite'.format(self.mountpoint_url)

        self.echo.start()
        req = requests.post(create_plone_url, params, auth=self.auth)
        self.echo.stop()
        if req.status_code not in [302, 200, 204, 201]:
            return error_log('Error creating Plone site at {}'.format(self.site_url))
        else:
            return success_log('Successfully created Plone site at {}'.format(self.site_url))

    def setup_homepage(self):
        setup_view_url = '{}/setuphomepage'.format(self.site_url)
        req = requests.get(setup_view_url, auth=self.auth)
        if req.status_code not in [302, 200, 204, 201]:
            return error_log('Error on hompepage setup'.format(self.site_url))
        else:
            return success_log('Successfully configured homepage'.format(self.site_url))

    def rebuild_catalog(self):
        recatalog_url = '{}/portal_catalog?manage_catalogRebuild:method=+Clear+and+Rebuild+'.format(self.site_url)
        resp = requests.get(recatalog_url, auth=self.auth)
        if resp.status_code not in [302, 200, 204, 201] or 'Catalog Rebuilt' not in resp.content:
            return error_log('Error on rebuilding catalog'.format(self.site_url))
        else:
            return success_log('Successfully rebuild site catalog'.format(self.site_url))

    def setup_ldap(self, branch, ldap_config):
        setup_view_url = '{}/setupldap'.format(self.site_url)
        params = {
            "ldap_name": ldap_config.name,
            "ldap_server": re.sub(r'ldaps?:\/\/', '', ldap_config.server),
            "branch_name": branch,
            "base_dn": ldap_config.branches.base_dn,
            "branch_admin_cn": ldap_config.branches.admin_cn,
            "branch_admin_password": ldap_config.branches.admin_password,
            "allow_manage_users": True
        }

        req = requests.post(setup_view_url, data=params, auth=self.auth)

        if req.status_code not in [302, 200, 204, 201]:
            return error_log('Error on ldap branch "{}" setup'.format(branch))
        else:
            return success_log('Successfully configured ldap branch "{}"'.format(branch))


class GenwebServer(object):
    _remote_config_files = {}

    def __init__(self, config, *args, **kwargs):
        self.config = config

    def get_environment(self, server):
        return [a for a in self.config.environments if a['server'] == server][0]

    def is_mountpoint_available(self, environment, mountpoint_id, allow_shared=False):
        mountpoints = self.get_mountpoints()
        for mountpoint in mountpoints:
            # Filter out non-official mountpoints
            if mountpoint_id == mountpoint['id'] and mountpoint['environment'] == environment:
                if not mountpoint['instances'] or allow_shared:
                    return True

        return False

    def get_available_mountpoint(self):
        available = []
        mountpoints = self.get_mountpoints()

        for mountpoint in mountpoints:
            # Filter out non-official mountpoints
            if mountpoint['id'].isdigit():
                if not mountpoint['instances']:
                    available.append(mountpoint)

        if available:
            sorted_mountpoints = sorted(available, key=lambda mountpoint: mountpoint['id'])
            return sorted_mountpoints[0]
        else:
            return None

    def get_mountpoints(self):
        mountpoints = {}

        for environment in self.config.environments:
            auth = (environment['admin_username'], environment['admin_password'])
            port = GENWEB_ZOPE_CLIENT_BASE_PORT + 1
            resp = requests.get(
                "http://{}:{}/manage_menu".format(environment['server'], port),
                auth=auth)

            expanded_menu = PyQuery(resp.content).find('table tr a[href*=tree-e]').attr('href')
            resp = requests.get(
                "http://{}:{}/{}".format(environment['server'], port, expanded_menu),
                auth=auth)

            table = PyQuery(resp.content).find('table')[1]
            rows = PyQuery(table).find('tr')
            current_mountpoint = None
            for tr in rows:
                ptr = PyQuery(tr)
                is_mountpoint = ptr.find('img[alt=Folder]')
                is_plone = ptr.find('img[alt="Plone Site"]') and len(ptr.find('td')) == 3
                if is_mountpoint:
                    current_mountpoint = ptr.find('td a')[-1].text
                    mountpoints.setdefault(current_mountpoint, {
                        'id': current_mountpoint,
                        'instances': [],
                        'port': GENWEB_ZOPE_CLIENT_BASE_PORT + 1,
                        'environment': environment['server'],
                    })
                elif is_plone:
                    current_plone = ptr.find('td a')[-1].text
                    instance_info = self.get_instance(environment, current_mountpoint, current_plone)
                    plone_instance = OrderedDict()
                    plone_instance['environment'] = environment['server']
                    plone_instance['mountpoint'] = current_mountpoint
                    plone_instance['plonesite'] = current_plone
                    plone_instance['url'] = 'http://{}:{}/{}/{}'.format(
                        environment['server'],
                        port,
                        current_mountpoint,
                        current_plone

                    )
                    mountpoints[current_mountpoint]['instances'].append(plone_instance)

        return mountpoints.values()

    def get_instances(self):
        instances = []
        for mountpoint in self.get_mountpoints():
            instances.extend(mountpoint['instances'])
        return instances

    def new_instance(self, instance_name, environment, mountpoint, title, language, ldap_branch, ldap_password, logecho):

        environment = self.get_environment(environment)

        site = Plone(environment, mountpoint, instance_name, title, language, logecho)

        yield step_log('Creating Plone site')
        yield site.create(packages=['genweb.core:default'])

        yield step_log('Setting up homepage')
        yield site.setup_homepage()

        yield step_log('Setting up ldap')
        yield site.setup_ldap(branch=ldap_branch, password=ldap_password)

    def get_instance(self, env, mountpoint, plonesite):

        return {
        }
