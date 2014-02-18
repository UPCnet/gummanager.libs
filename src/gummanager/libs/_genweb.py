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
from gummanager.libs.utils import padded_error

import tarfile
from StringIO import StringIO
from collections import OrderedDict
from pyquery import PyQuery
import requests


class GenwebServer(object):
    _remote_config_files = {}
    def __init__(self, *args, **kwargs):
        for k,v in kwargs.items():
            setattr(self, k, v)

    def get_instances(self):
        instances = []

        for environment in self.environments:
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
                elif is_plone:
                    current_plone = ptr.find('td a')[-1].text
                    instance_info = self.get_instance('{}/{}'.format(current_mountpoint, current_plone))
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
                    instances.append(plone_instance)

        return instances

    def new_instance(self, instance_name):

        siteid = 'instance_name'
        environment = self.environments[0]
        title = siteid.capitalize()
        language = 'ca'
        mountpoint = '1'

        # Check if site exists

        AUTH = (environment['admin_username'], environment['admin_password'])

        genweb_base_url = 'http://{}:{}'.format(
            environment['server'],
            GENWEB_ZOPE_CLIENT_BASE_PORT + 1
        )

        #Create Plone Site
        print "Creating Plone Site"
        params = {
            "site_id": siteid,
            "title": title,
            "default_language": language,
            "setup_content:boolean": True,
            "extension_ids:list": [
                'plonetheme.classic:default',
                'plonetheme.sunburst:default',
                'genweb.core:default'
            ],
            "form.submitted:boolean": True,
            "submit": "Crear lloc Plone"
        }

        manage_plone_url = '{}/{}/{}/manage' % (genweb_base_url, mountpoint, siteid)

        req = requests.post('%s/%s/@@plone-addsite' % (genweb_base_url, siteid), params, auth=AUTH)
        if req.status_code not in [302, 200]:
            padded_error('Hi ha hagut algun error al afegir el plone a <a href="{}">{}</a>. Ja existeix?'.format(manage_plone_url, manage_plone_url))

        req = requests.get('%s/%s/%s' % (genweb_base_url, siteid, siteid), auth=AUTH,)

        if 'titol-eines-usuari' not in req.content:
            padded_error('Hi ha hagut algun error instalant el genweb a <a href="{}">{}</a'.format(manage_plone_url, manage_plone_url))

    def get_instance(self, instance_path):
        mountpoint, plonesite = instance_path.split('/')

        return {
        }

