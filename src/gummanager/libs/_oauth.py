from gummanager.libs.utils import RemoteConnection
from gummanager.libs.utils import configure_ini
from gummanager.libs.utils import parse_ini_from
from gummanager.libs.utils import circus_status
from gummanager.libs.utils import progress_log, padded_success, padded_error
from gummanager.libs.ports import CIRCUS_HTTPD_BASE_PORT
from gummanager.libs.ports import CIRCUS_TCP_BASE_PORT
from gummanager.libs.ports import OSIRIS_BASE_PORT
from gummanager.libs.buildout import RemoteBuildoutHelper

from gummanager.libs.config_files import LDAP_INI
from gummanager.libs.config_files import INIT_D_SCRIPT
from gummanager.libs.config_files import OSIRIS_NGINX_ENTRY

from collections import OrderedDict


class OauthServer(object):

    def __init__(self, *args, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

        self.remote = RemoteConnection(self.ssh_user, self.server)
        self.buildout = RemoteBuildoutHelper(self.remote, self.python_interpreter, self)

    def get_instances(self):
        instances = []
        for instance_name in self.buildout.config_files:
            instance = self.get_instance(instance_name)
            if instance:
                instances.append(instance)
        return instances

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
            'direct': 'http://{}:{}'.format(self.server, osiris['server:main']['port']),
            'dns': 'https://{}/{}'.format(self.server_dns, instance_name)
        }
        instance['ldap'] = {
            'server': ldap['ldap']['server'],
            'basedn': ldap['ldap']['userbasedn']
        }
        instance['circus'] = 'http://{}:{}'.format(self.server, CIRCUS_HTTPD_BASE_PORT + port_index)
        instance['circus_tcp'] = 'tcp://{}:{}'.format(self.server, CIRCUS_TCP_BASE_PORT + port_index)

        return instance

    def instance_by_port_index(self, port_index):
        instances = self.get_instances()
        for instance in instances:
            if instance['port_index'] == port_index:
                return instance
        return None

    def get_available_port(self):
        instances = self.get_instances()
        ports = [instance['port_index'] for instance in instances]
        ports.sort()
        return ports[-1] + 1 if ports else 1

    def new_instance(self, instance_name, port_index, ldap_branch=None):

        ldap_name = ldap_branch if ldap_branch is not None else instance_name
        repo_url = 'https://github.com/UPCnet/maxserver'
        new_instance_folder = '{}/{}'.format(
            self.instances_root,
            instance_name
        )

        self.buildout.folder = new_instance_folder
        print """
    Adding a new osiris OAuth server:
        name: "{}"
        server: "{}"
        port_index: "{}"
        ldap_branch: "{}"

        """.format(instance_name, self.server, port_index, ldap_name)

        if self.remote.file_exists('{}'.format(new_instance_folder)):
            padded_error('Folder {} already exists'.format(new_instance_folder))
            return None

        ###########################################################################################
        progress_log('Cloning buildout')

        success = self.buildout.clone(repo_url)

        if success:
            padded_success('Succesfully cloned repo at {}'.format(new_instance_folder))
        else:
            padded_error('Error when cloning repo')
            return None

        ###########################################################################################

        progress_log('Bootstraping buildout')

        success = self.buildout.bootstrap('osiris-only.cfg')

        if success:
            padded_success('Succesfully bootstraped buildout {}'.format(new_instance_folder))
        else:
            padded_error('Error on bootstraping')
            return None

        ###########################################################################################

        progress_log('Configuring customizeme.cfg')

        customizations = {
            'hosts': {
                'main': self.server_dns,
                'rabbitmq': self.rabbitmq_server,
                'mongodb_cluster': self.mongodb_cluster
            },
            'max': {
                'name': instance_name,
            },
            'ports': {
                'port_index': port_index,
            },

        }

        success = self.buildout.configure_file('customizeme.cfg', customizations)

        if success:
            padded_success('Succesfully configured {}/customizeme.cfg'.format(new_instance_folder))
        else:
            padded_error('Error on applying settings on customizeme.cfg')
            return None

        ###########################################################################################

        progress_log('Generating ldap.ini')
        ldapini = configure_ini(
            string=LDAP_INI,
            params={
                'ldap': {
                    'server': self.ldap_config['server'],
                    'userbind': 'cn=ldap,ou={},dc=upcnet,dc=es'.format(ldap_name),
                    'userbasedn': 'ou={},dc=upcnet,dc=es'.format(ldap_name),
                    'groupbasedn': 'ou=groups,ou={},dc=upcnet,dc=es'.format(ldap_name)
                }
            }
        )

        success = self.remote.put_file("{}/config/ldap.ini".format(new_instance_folder), ldapini)

        if success:
            padded_success('Succesfully created {}/config/ldap.ini'.format(new_instance_folder))
        else:
            padded_error('Error when generating ldap.ini')
            return None

        ###########################################################################################

        progress_log('Creating nginx entry')
        nginx_params = {
            'instance_name': instance_name,
            'server_dns': self.server_dns,
            'osiris_port': int(port_index) + OSIRIS_BASE_PORT
        }
        nginxentry = OSIRIS_NGINX_ENTRY.format(**nginx_params)

        success = self.remote.put_file("{}/config/osiris-instances/{}.conf".format(self.nginx_root, instance_name), nginxentry)

        if success:
            padded_success("Succesfully created {}/config/osiris-instances/{}.conf".format(self.nginx_root, instance_name))
        else:
            padded_error('Error when generating nginx config file')
            return None

        ###########################################################################################

        progress_log('Generating init.d script')
        initd_params = {
            'port_index': port_index,
            'instance_folder': new_instance_folder
        }
        initd_script = INIT_D_SCRIPT.format(**initd_params)

        success = self.remote.put_file("/etc/init.d/oauth_{}".format(instance_name), initd_script)

        code, stdout = self.remote.execute("chmod +x /etc/init.d/oauth_{}".format(instance_name))
        if code != 0:
            success = False

        code, stdout = self.remote.execute("update-rc.d oauth_{} defaults".format(instance_name))
        if code != 0:
            success = False

        if success:
            padded_success("Succesfully created /etc/init.d/oauth_{}".format(instance_name))
        else:
            padded_error('Error when generating init.d script')
            return None

        ###########################################################################################

        progress_log('Executing buildout')

        success = self.buildout.execute()
        if success:
            padded_error("Error on buildout execution")
            return None
        else:
            padded_success("Succesfully created a new oauth instance")
