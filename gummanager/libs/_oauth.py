from gummanager.libs.utils import RemoteConnection
from gummanager.libs.utils import configure_ini
from gummanager.libs.utils import parse_ini_from, error_log, success, step_log, success_log, StepError
from gummanager.libs.utils import circus_status, circus_control
from gummanager.libs.utils import progress_log, padded_success, padded_error, padded_log
from gummanager.libs.ports import CIRCUS_HTTPD_BASE_PORT
from gummanager.libs.ports import CIRCUS_TCP_BASE_PORT
from gummanager.libs.ports import CIRCUS_NGINX_BASE_PORT
from gummanager.libs.ports import OSIRIS_BASE_PORT
from gummanager.libs.buildout import RemoteBuildoutHelper

from gummanager.libs.config_files import LDAP_INI
from gummanager.libs.config_files import INIT_D_SCRIPT
from gummanager.libs.config_files import OSIRIS_NGINX_ENTRY
from gummanager.libs.config_files import CIRCUS_NGINX_ENTRY

from collections import OrderedDict, namedtuple
from time import sleep
import re


class OauthServer(object):

    def __init__(self, config, *args, **kwargs):
        self.config = config

        self.remote = RemoteConnection(self.config.ssh_user, self.config.server)
        self.buildout = RemoteBuildoutHelper(self.remote, self.config.python_interpreter, self)

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

    def reload_nginx_configuration(self):
        progress_log('Reloading nginx configuration')
        padded_log('Testing configuration')
        code, stdout = self.remote.execute('/etc/init.d/nginx configtest')
        if code == 0 and 'done' in stdout:
            padded_success('Configuration test passed')
        else:
            padded_error('Configuration test failed')
            return None

        code, stdout = self.remote.execute('/etc/init.d/nginx reload')
        if code == 0 and 'done' in stdout:
            padded_success('Nginx reloaded succesfully')
        else:
            padded_error('Error reloading nginx')
            return None

    def start(self, instance_name):
        progress_log('Starting instance')
        status = self.get_status(instance_name)
        instance = self.get_instance(instance_name)

        if status['status'] == 'unknown':
            padded_log('Circus stopped, starting circusd ...')
            code, stdout = self.remote.execute('/etc/init.d/oauth_{} start'.format(instance_name))
        elif status['status'] == 'stopped':
            padded_log('Osiris stopped, starting process ...')
            circus_control(
                'start',
                endpoint=instance['circus_tcp'],
                process='osiris'
            )

        padded_log('Waiting for circus...')
        sleep(1)
        status = self.get_status(instance_name)
        if status['status'] == 'active':
            padded_success('Oauth instance {} started'.format(instance_name))
        else:
            padded_error('Oauth instance {} not started'.format(instance_name))

    def stop(self, instance_name):
        progress_log('Stopping instance')
        instance = self.get_instance(instance_name)
        circus_control(
            'stop',
            endpoint=instance['circus_tcp'],
            process='osiris'
        )

        padded_log('Waiting for circus to shutdown...')
        sleep(1)
        status = self.get_status(instance_name)
        if status['status'] == 'stopped':
            padded_success('Osiris OAuth instance {} stopped'.format(instance_name))
        else:
            padded_error('Osiris OAuth instance {} still active'.format(instance_name))

    def get_status(self, instance_name):
        instance = self.get_instance(instance_name)
        status = circus_status(
            endpoint=instance['circus_tcp'],
            process='osiris'
        )

        result_status = OrderedDict()
        result_status['name'] = instance_name
        result_status['server'] = instance['server']
        result_status['status'] = status['status']
        result_status['pid'] = status['pid']
        result_status['uptime'] = status['uptime']
        return result_status

    def get_instance(self, instance_name):
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
        instance['circus'] = 'http://{}:{}'.format(self.config.server, CIRCUS_HTTPD_BASE_PORT + port_index)
        instance['circus_tcp'] = 'tcp://{}:{}'.format(self.config.server, CIRCUS_TCP_BASE_PORT + port_index)

        return instance

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
            'hosts': {
                'main': self.config.server_dns,
                'rabbitmq': self.config.rabbitmq_server,
                'mongodb_cluster': self.config.mongodb_cluster
            },
            'max-config': {
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
                    'userbind': 'cn=ldap,ou={},dc=upcnet,dc=es'.format(self.instance.ldap),
                    'userbasedn': 'ou={},dc=upcnet,dc=es'.format(self.instance.ldap),
                    'groupbasedn': 'ou=groups,ou={},dc=upcnet,dc=es'.format(self.instance.ldap)
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

    def create_circus_nginx_entry(self):

        circus_nginx_params = {
            'circus_nginx_port': int(self.instance.index) + CIRCUS_NGINX_BASE_PORT,
            'circus_httpd_endpoint': int(self.instance.index) + CIRCUS_HTTPD_BASE_PORT
        }
        circus_nginxentry = CIRCUS_NGINX_ENTRY.format(**circus_nginx_params)
        nginx_file_location = "{}/config/circus-instances/{}.conf".format(self.config.nginx_root, self.instance.name)

        self.remote.put_file(nginx_file_location, circus_nginxentry),
        return success_log("Succesfully created {}".format(nginx_file_location))

    def create_startup_script(self):
        initd_params = {
            'port_index': int(self.instance.index) + CIRCUS_TCP_BASE_PORT,
            'instance_folder': self.buildout.folder
        }
        initd_script = INIT_D_SCRIPT.format(**initd_params)

        init_d_script_name = "oauth_{}".format(self.instance.name)
        init_d_script_location = "/etc/init.d/{}".format(init_d_script_name)

        self.remote.put_file(init_d_script_location, initd_script)
        self.remote.execute("chmod +x {}".format(init_d_script_location), do_raise=True)
        self.remote.execute("update-rc.d {} defaults".format(init_d_script_name), do_raise=True)

        return success_log("Succesfully created /etc/init.d/max_{}".format(self.instance.name))

    def execute_buildout(self):
        self.buildout.execute()
        return success_log("Succesfully created a new oauth instance")

    def commit_local_changes(self):
        self.buildout.commit_to_local_branch(self.config.local_git_branch)
        return success_log("Succesfully commited local changes")

    def set_filesystem_permissions(self):
        self.buildout.change_permissions(self.config.process_uid)
        return success_log("Succesfully changed permissions")

    def new_instance(self, instance_name, port_index, ldap_branch=None, logecho=None):

        self.buildout.cfgfile = 'max-only.cfg'
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

            yield step_log('Configuring ldap.ini')
            yield self.configure_ldap()

            yield step_log('Creating nginx entry for oauth')
            yield self.create_max_nginx_entry()

            yield step_log('Creating nginx entry for circus')
            yield self.create_circus_nginx_entry()

            yield step_log('Creating init.d script')
            yield self.create_startup_script()

            yield step_log('Executing buildout')
            yield self.execute_buildout()

            yield step_log('Commiting to local branch')
            yield self.commit_local_changes()

            yield step_log('Changing permissions')
            yield self.set_filesystem_permissions()

        except StepError as error:
            yield error.message