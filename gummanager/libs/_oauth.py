# -*- coding: utf-8 -*-
from collections import OrderedDict
from gummanager.libs.buildout import RemoteBuildoutHelper
from gummanager.libs.config_files import LDAP_INI
from gummanager.libs.config_files import OSIRIS_NGINX_ENTRY
from gummanager.libs.mixins import CommonSteps
from gummanager.libs.mixins import NginxHelpers
from gummanager.libs.mixins import SupervisorHelpers
from gummanager.libs.mixins import TokenHelper
from gummanager.libs.ports import OSIRIS_BASE_PORT
from gummanager.libs.pyramid import PyramidServer
from gummanager.libs.utils import RemoteConnection
from gummanager.libs.utils import StepError
from gummanager.libs.utils import command
from gummanager.libs.utils import configure_ini
from gummanager.libs.utils import error_log, raising_error_log, success
from gummanager.libs.utils import message_log
from gummanager.libs.utils import parse_ini_from
from gummanager.libs.utils import step_log
from gummanager.libs.utils import success_log

import re
import requests
from time import sleep


class OauthServer(SupervisorHelpers, NginxHelpers, CommonSteps, TokenHelper, PyramidServer):

    def __init__(self, config, *args, **kwargs):
        self.config = config

        self._instances = {}
        self.process_prefix = 'osiris_'
        self.remote = RemoteConnection(self.config.ssh_user, self.config.server)
        self.buildout = RemoteBuildoutHelper(self.remote, self.config.python_interpreter, self)

        if not self.remote.file_exists(self.config.instances_root):
            self.remote.mkdir(self.config.instances_root)

    def update_buildout(self):
        result = self.buildout.upgrade(self.config.maxserver_buildout_branch, self.config.local_git_branch)
        return success(result, "Succesfully commited local changes")

    def reload_instance(self):
        self.restart(self.instance.name)
        sleep(1)
        status = self.get_status(self.instance.name)
        if status['status'] == 'running':
            return success_log("Succesfully restarted oauth {}".format(self.instance.name))
        else:
            return error_log('Oauth instance {} is not running'.format(self.instance.name))

    def get_instance(self, instance_name):
        if instance_name not in self._instances:
            osiris_ini = self.buildout.config_files[instance_name].get('osiris.ini', '')
            if not osiris_ini:
                return {}
            osiris = parse_ini_from(osiris_ini)

            ldap_ini = self.buildout.config_files[instance_name].get('ldap.ini', '')
            if not ldap_ini:
                return {}
            ldap = parse_ini_from(ldap_ini)

            port_index = int(osiris['server:main']['port']) - OSIRIS_BASE_PORT

            instance = OrderedDict()
            instance['name'] = instance_name
            instance['port_index'] = port_index
            instance['mongo_database'] = osiris['app:main']['osiris.store.db']
            instance['server'] = {
                'direct': 'http://{}:{}'.format(self.config.server, osiris['server:main']['port']),
                'dns': 'https://{}/{}'.format(self.config.server_dns, instance_name)
            }

            instance['ldap'] = {
                'server': ldap['ldap']['server'],
                'basedn': ldap['ldap']['userbasedn'],
                'branch': re.match(r"ou=(.*?),", ldap['ldap']['userbasedn']).groups()[0]
            }
            self._instances[instance_name] = instance
        return self._instances[instance_name]

    def test(self, instance_name, username, password):
        instance = self.get_instance(instance_name)
        try:
            yield step_log('Testing oauth server @ {}'.format(instance['server']['dns']))

            yield message_log('Checking server health')

            try:
                status = requests.get(instance['server']['dns'], verify=True).status_code
            except requests.exceptions.SSLError:
                yield error_log('SSL certificate verification failed')
                yield message_log('Continuing test without certificate check')

            try:
                status = requests.get(instance['server']['dns'], verify=False).status_code
            except requests.ConnectionError:
                yield raising_error_log('Connection error, check nginx is running, and dns resolves as expected.')
            except:
                yield raising_error_log('Unknown error trying to access oauth server. Check params and try again')
            else:
                if status == 500:
                    yield raising_error_log('Error on oauth server, Possible causes:\n  - ldap configuration error (bad server url?)\n  - Mongodb configuration error (bad replicaset name or hosts list?)\nCheck osiris log for more information.')
                elif status == 502:
                    yield raising_error_log('Server not respoding at {}. Check that:\n  - osiris process is running\n  - nginx upstream definition is pointing to the right host:port.'.format(instance['server']['dns']))
                elif status == 504:
                    yield raising_error_log('Gateway timeout. Probably oauth server is giving timeout trying to contact ldap server')
                elif status == 404:
                    yield raising_error_log('There\'s no oauth server at {}. Chech there\'s an nginx entry for this server.'.format(instance['server']['dns']))
                elif status != 200:
                    yield raising_error_log('Server {} responded with {} code. Check osiris logs.'.format(instance['server']['dns'], status))

            yield message_log('Retrieving token for "{}"'.format(username))
            token = self.get_token(instance['server']['dns'], username, password)
            succeeded_retrieve_token = token is not None

            if not succeeded_retrieve_token:
                yield raising_error_log('Error retreiving token. Check username/password and try again')

            yield message_log('Checking retreived token')
            succeeded_check_token = self.check_token(instance['server']['dns'], username, token)

            if not succeeded_check_token:
                yield raising_error_log('Error retreiving token')

            if succeeded_check_token and succeeded_retrieve_token:
                yield success_log('Oauth server check passed')
            else:
                yield raising_error_log('Oauth server check failed')

        except StepError as error:
            yield error_log(error.message)

    # Steps used in commands. Some of them defined in gummanager.libs.mixins

    def configure_instance(self):
        customizations = {
            'mongodb-config': {
                'replica_set': self.config.mongodb.replica_set,
                'cluster_hosts': self.config.mongodb.cluster
            },
            'osiris-config': {
                'name': self.instance.name,
            },
            'ports': {
                'port_index': '{:0>2}'.format(self.instance.index),
            },

        }

        self.buildout.configure_file('customizeme.cfg', customizations),
        return success_log('Succesfully configured {}/customizeme.cfg'.format(self.buildout.folder))

    def configure_ldap(self):
        """
            Configure the right settings for ldap based on if :
            branches option enabled or disabled
        """

        if self.config.ldap.branches.enabled:
            effective_admin_dn = 'cn={admin_cn},ou={branch},{base_dn}'.format(branch=self.instance.ldap, **self.config.ldap.branches)
            effective_admin_password = self.config.ldap.branches.admin_password
            effective_users_base_dn = 'ou={},{}'.format(self.instance.ldap, self.config.ldap.branches.base_dn)
            effective_groups_base_dn = 'ou=groups,ou={},{}'.format(self.instance.ldap, self.config.ldap.branches.base_dn)
        else:
            effective_admin_dn = self.config.ldap.admin_dn
            effective_admin_password = self.config.ldap.admin_password
            effective_users_base_dn = self.config.ldap.users_base_dn
            effective_groups_base_dn = self.config.ldap.group_base_dn

        ldapini = configure_ini(
            string=LDAP_INI,
            params={
                'ldap': {
                    'server': self.config.ldap.server,
                    'password': effective_admin_password,
                    'userbind': effective_admin_dn,
                    'userbasedn': effective_users_base_dn,
                    'groupbasedn': effective_groups_base_dn
                }
            }
        )
        ldap_ini_location = "{}/config/ldap.ini".format(self.buildout.folder)
        self.remote.put_file(ldap_ini_location, ldapini)
        return success_log('Succesfully configured {}'.format(ldap_ini_location))

    def create_oauth_nginx_entry(self):
        global_allowed_ips = self.config.oauth.allowed_ips
        instance_allowed_ips = []
        allowed_ips = global_allowed_ips + instance_allowed_ips
        nginx_params = {
            'instance_name': self.instance.name,
            'server': self.config.oauth.server,
            'server_dns': self.config.oauth.server_dns,
            'osiris_port': int(self.instance.index) + OSIRIS_BASE_PORT,
            'buildout_folder': self.config.nginx.root,
            'allowed_ips': '\n      '.join(['allow {};'.format(ip) for ip in allowed_ips])
        }
        nginxentry = OSIRIS_NGINX_ENTRY.format(**nginx_params)

        nginx_remote = RemoteConnection(self.config.nginx.ssh_user, self.config.nginx.server)
        nginx_file_location = "{}/config/osiris-instances/{}.conf".format(self.config.nginx.root, self.instance.name)
        nginx_remote.put_file(nginx_file_location, nginxentry)
        return success_log("Succesfully created {}".format(nginx_file_location))

    def backup_nginx_configuration(self):
        nginx_remote = RemoteConnection(self.config.nginx.ssh_user, self.config.nginx.server)

        nginx_file_location = "{}/config/osiris-instances/{}.conf".format(self.config.nginx.root, self.instance.name)
        backup_file_location = "{}/config/osiris-instances/{}.conf.backup".format(self.config.nginx.root, self.instance.name)
        backup_content = nginx_remote.get_file(nginx_file_location)
        nginx_remote.put_file(backup_file_location, backup_content)
        return success_log("Succesfully backed up to {}".format(backup_file_location))

    def recover_nginx_configuration(self):
        nginx_remote = RemoteConnection(self.config.nginx.ssh_user, self.config.nginx.server)

        nginx_file_location = "{}/config/osiris-instances/{}.conf".format(self.config.nginx.root, self.instance.name)
        backup_file_location = "{}/config/osiris-instances/{}.conf.backup".format(self.config.nginx.root, self.instance.name)
        backup_content = nginx_remote.get_file(backup_file_location)
        nginx_remote.put_file(nginx_file_location, backup_content)
        return success_log("Succesfully recovered backup from".format(backup_file_location))

    def commit_local_changes(self):
        self.buildout.commit_to_local_branch(
            self.config.local_git_branch,
            files=[
                'customizeme.cfg',
                'mongoauth.cfg'
            ])
        return success_log("Succesfully commited local changes")

    # COMMANDS

    @command
    def new_instance(self, instance_name, port_index, ldap_branch=None, logecho=None):

        self.buildout.cfgfile = self.config.oauth.cfg_file
        self.buildout.logecho = logecho
        self.buildout.folder = '{}/{}'.format(
            self.config.instances_root,
            instance_name
        )

        self.set_instance(
            name=instance_name,
            index=port_index,
            ldap=ldap_branch if ldap_branch is not None else instance_name
        )

        yield step_log('Cloning buildout')
        yield self.clone_buildout()

        yield step_log('Bootstraping buildout')
        yield self.bootstrap_buildout()

        yield step_log('Configuring customizeme.cfg')
        yield self.configure_instance()

        yield step_log('Configuring mongoauth.cfg')
        yield self.configure_mongoauth()

        yield step_log('Configuring ldap.ini')
        yield self.configure_ldap()

        yield step_log('Creating nginx entry for oauth')
        yield self.create_oauth_nginx_entry()

        yield step_log('Executing buildout')
        yield self.execute_buildout()

        yield step_log('Commiting to local branch')
        yield self.commit_local_changes()

        yield step_log('Changing permissions')
        yield self.set_filesystem_permissions()

        yield step_log('Adding instance to supervisor config')
        yield self.configure_supervisor()

    @command
    def upgrade(self, instance_name, logecho=None):
        self.buildout.cfgfile = self.config.oauth.cfg_file
        self.buildout.logecho = logecho
        self.buildout.folder = '{}/{}'.format(
            self.config.instances_root,
            instance_name
        )

        self.set_instance(
            name=instance_name,
        )

        yield step_log('Updating buildout')
        yield self.update_buildout()

        yield step_log('Executing buildout')
        yield self.execute_buildout(update=True)

        yield step_log('Changing permissions')
        yield self.set_filesystem_permissions()

        # yield step_log('Reloading oauth')
        yield self.reload_instance()

    @command
    def reconfigure_nginx(self, instance_name):
        instance = self.get_instance(instance_name)
        self.set_instance(
            name=instance_name,
            index=instance['port_index']

        )

        yield step_log('Backing up current configuration')
        yield self.backup_nginx_configuration()

        yield step_log('Creating nginx entry for oauth')
        yield self.create_oauth_nginx_entry()

        yield step_log('Testing new nginx configuration')
        status = self.test_nginx()
        if status[0] == 0:
            self.recover_nginx_configuration()
        yield status
        import ipdb;ipdb.set_trace()
        yield step_log('Reloading nginx')
        yield self.reload_nginx()
