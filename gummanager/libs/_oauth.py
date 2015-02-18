from gummanager.libs.utils import RemoteConnection
from gummanager.libs.utils import configure_ini
from gummanager.libs.utils import parse_ini_from, error_log, success, step_log, success_log, StepError
from gummanager.libs.utils import message_log
from gummanager.libs.ports import OSIRIS_BASE_PORT
from gummanager.libs.buildout import RemoteBuildoutHelper
from gummanager.libs.mixins import ProcessHelper

from gummanager.libs.config_files import LDAP_INI
from gummanager.libs.config_files import OSIRIS_NGINX_ENTRY

from collections import OrderedDict, namedtuple
import re


class OauthServer(ProcessHelper, object):

    def __init__(self, config, *args, **kwargs):
        self.config = config

        self._instances = {}
        self.process_prefix = 'osiris_'
        self.remote = RemoteConnection(self.config.ssh_user, self.config.server)
        self.buildout = RemoteBuildoutHelper(self.remote, self.config.python_interpreter, self)

        if not self.remote.file_exists(self.config.instances_root):
            self.remote.mkdir(self.config.instances_root)

    def get_instances(self):
        instances = []
        for instance_name in self.buildout.config_files:
            instance = self.get_instance(instance_name)
            if instance:
                instances.append(instance)
        return instances

    def set_instance(self, **kwargs):
        InstanceData = namedtuple('InstanceData', kwargs.keys())
        self.instance = InstanceData(**kwargs)

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
            instance['supervisor_xmlrpc'] = 'http://admin:{}@{}:{}/RPC2'.format(
                self.config.supervisor.password,
                self.config.server,
                self.config.supervisor.port)
            self._instances[instance_name] = instance
        return self._instances[instance_name]

    def instance_by_port_index(self, port_index):
        instances = self.get_instances()
        for instance in instances:
            if instance['port_index'] == port_index:
                return instance
        return None

    def instance_by_dns(self, dns):
        instances = self.get_instances()
        for instance in instances:
            if instance['server']['dns'] == dns:
                return instance
        return None

    def get_available_port(self):
        instances = self.get_instances()
        ports = [instance['port_index'] for instance in instances]
        ports.sort()
        return ports[-1] + 1 if ports else 1

    def reload_nginx_configuration(self):
        try:
            yield step_log('Reloading nginx configuration')
            yield message_log('Testing configuration')

            yield self.test_nginx()
            yield self.reload_nginx()
        except StepError as error:
            yield error_log(error.message)

    # Steps

    def clone_buildout(self):
        repo_url = 'https://github.com/UPCnet/maxserver'

        if self.remote.file_exists('{}'.format(self.buildout.folder)):
            return error_log('Folder {} already exists'.format(self.buildout.folder))

        return success(
            self.buildout.clone(repo_url),
            'Succesfully cloned repo at {}'.format(self.buildout.folder)
        )

    def bootstrap_buildout(self):
        return success(
            self.buildout.bootstrap(),
            'Succesfully bootstraped buildout {}'.format(self.buildout.folder)
        )

    def configure_instance(self):
        customizations = {
            'mongodb-config': {
                'replica_set': self.config.replica_set,
                'cluster_hosts': self.config.mongodb_cluster
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

        ldapini = configure_ini(
            string=LDAP_INI,
            params={
                'ldap': {
                    'server': self.config.ldap_config['server'],
                    'password': self.config.ldap_config['branch_admin_password'],
                    'userbind': 'cn={},ou={},{}'.format(
                        self.config.ldap_config['branch_admin_cn'],
                        self.instance.ldap,
                        self.config.ldap_config['base_dn']),
                    'userbasedn': 'ou={},{}'.format(
                        self.instance.ldap,
                        self.config.ldap_config['base_dn']),
                    'groupbasedn': 'ou=groups,ou={},{}'.format(
                        self.instance.ldap,
                        self.config.ldap_config['base_dn'])
                }
            }
        )
        ldap_ini_location = "{}/config/ldap.ini".format(self.buildout.folder)
        self.remote.put_file(ldap_ini_location, ldapini)
        return success_log('Succesfully configured {}'.format(ldap_ini_location))

    def create_max_nginx_entry(self):

        nginx_params = {
            'instance_name': self.instance.name,
            'server_dns': self.config.server_dns,
            'osiris_port': int(self.instance.index) + OSIRIS_BASE_PORT
        }
        nginxentry = OSIRIS_NGINX_ENTRY.format(**nginx_params)

        nginx_file_location = "{}/config/osiris-instances/{}.conf".format(self.config.nginx_root, self.instance.name)
        self.remote.put_file(nginx_file_location, nginxentry)
        return success_log("Succesfully created {}".format(nginx_file_location))

    def execute_buildout(self):
        self.buildout.execute()
        return success_log("Succesfully created a new oauth instance")

    def configure_supervisor(self):
        new_instance_folder = '{}/{}'.format(
            self.config.instances_root,
            self.instance.name
        )

        settings = {
            'supervisor': {'parts': [new_instance_folder]}
        }

        remote_file = "{}/customizeme.cfg".format(self.config.supervisor.path)
        customizeme = configure_ini(
            string=self.remote.get_file(remote_file),
            append=True,
            params=settings)

        successfull = self.remote.put_file("{}/{}".format(self.config.supervisor.path, 'customizeme.cfg'), customizeme)
        if not successfull:
            raise StepError('Error when configuring {}'.format(remote_file))

        code, stdout = self.remote.execute('cd {} && ./supervisor_config'.format(self.config.supervisor.path), do_raise=True)

        return success(
            stdout,
            "Succesfully added {} to supervisor".format(new_instance_folder)
        )

    def commit_local_changes(self):
        self.buildout.commit_to_local_branch(
            self.config.local_git_branch,
            files=[
                'customizeme.cfg',
                'mongoauth.cfg'
            ])
        return success_log("Succesfully commited local changes")

    def set_filesystem_permissions(self):
        self.buildout.change_permissions(self.config.process_uid)
        return success_log("Succesfully changed permissions")

    def new_instance(self, instance_name, port_index, ldap_branch=None, logecho=None):

        self.buildout.cfgfile = 'osiris-only.cfg'
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

        try:
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
            yield self.create_max_nginx_entry()

            yield step_log('Executing buildout')
            yield self.execute_buildout()

            yield step_log('Commiting to local branch')
            yield self.commit_local_changes()

            yield step_log('Changing permissions')
            yield self.set_filesystem_permissions()

            yield step_log('Adding instance to supervisor config')
            yield self.configure_supervisor()

        except StepError as error:
            yield error.message
