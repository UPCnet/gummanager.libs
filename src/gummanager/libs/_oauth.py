from gummanager.libs.utils import SSH
from gummanager.libs.utils import configure_ini
from gummanager.libs.utils import parse_ini_from
from gummanager.libs.ports import CIRCUS_HTTPD_BASE_PORT
from gummanager.libs.ports import CIRCUS_TCP_BASE_PORT
from gummanager.libs.ports import OSIRIS_BASE_PORT
from gummanager.libs.config_files import LDAP_INI
from gummanager.libs.config_files import INIT_D_SCRIPT
from gummanager.libs.config_files import OSIRIS_NGINX_ENTRY

import tarfile
from StringIO import StringIO
from collections import OrderedDict



class OauthServer(object):
    _remote_config_files = {}
    def __init__(self, *args, **kwargs):
        for k,v in kwargs.items():
            setattr(self, k, v)

        self.ssh = SSH(self.ssh_user, self.server)

    @property
    def remote_config_files(self):
        if not self._remote_config_files:
            code, stdout = self.ssh('cd {} && find . -wholename "./*/config/*.ini" | tar cv -O -T -'.format(self.instances_root))
            tar = tarfile.open(mode= "r:", fileobj = StringIO(stdout))
            for taredfile in tar.members:
                instance_name, config, filename = taredfile.name.strip('./').split('/')
                self._remote_config_files.setdefault(instance_name, {})
                extracted_file = tar.extractfile(taredfile.name)
                self._remote_config_files[instance_name][filename] = extracted_file.read()
        return self._remote_config_files


    def get_instances(self):
        instances = []
        for instance_name in self.remote_config_files:
            instance = self.get_instance(instance_name)
            if instance:
                instances.append(instance)
        return instances

    def get_instance(self, instance_name):
        osiris_ini = self.remote_config_files[instance_name].get('osiris.ini', '')
        if not osiris_ini:
            return {}
        osiris = parse_ini_from(osiris_ini)

        ldap_ini = self.remote_config_files[instance_name].get('ldap.ini', '')
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

    def get_available_port(self):
        instances = self.get_instances()
        ports = [instance['port_index'] for instance in instances]
        ports.sort()
        return ports[-1] + 1

    def new_instance(self, instance_name):
        repo_url = 'https://github.com/UPCnet/maxserver'
        new_instance_folder = '{}/{}'.format(
            self.instances_root, 
            instance_name
        )
        
        # Clone buildout repository
        print ' > cloning buildout'
        code, stdout = self.ssh('git clone {} {}'.format(
            repo_url, 
            new_instance_folder)
        )

        if code != 0 or 'Cloning into' not in stdout:
            return None

        print ' > bootstraping buildout'
        # Bootstrap instance
        code, stdout = self.ssh('cd {} && {} bootstrap.py -c osiris-only.cfg'.format(
            new_instance_folder,
            self.python_interpreter)
        )  

        if code != 0 or 'Generated script' not in stdout:
            return None

        print ' > configuring customizeme.cfg'
        # Configure customizeme.cfg
        port_index = '07'

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
        customizeme = configure_ini(
            url='https://raw.github.com/UPCnet/maxserver/master/customizeme.cfg',
            params=customizations)
        
        code, stdout = self.ssh("cat > {}/customizeme.cfg".format(new_instance_folder),_in=customizeme)

        if code != 0:
            return None

        print ' > generating ldap.ini'
        # Configure ldap.ini
        ldapini = configure_ini(
            string=LDAP_INI,
            params={
                'ldap': {
                    'server': self.ldap_config['server'],
                    'userbind': 'cn=ldap,ou={},dc=upcnet,dc=es'.format(instance_name),
                    'userbasedn': 'ou={},dc=upcnet,dc=es'.format(instance_name),
                    'groupbasedn': 'ou=groups,ou={},dc=upcnet,dc=es'.format(instance_name)
                }
            }
        )

        code, stdout = self.ssh("cat > {}/config/ldap.ini".format(new_instance_folder),_in=ldapini)

        
        # Create log folder
        print ' > creating log folder'
        code, stdout = self.ssh("mkdir -p {}/var/log".format(new_instance_folder))

        if code != 0:
            return None


        # Adding nginx entry

        nginx_params = {
            'instance_name': instance_name,
            'server_dns': self.server_dns,
            'osiris_port': int(port_index) + OSIRIS_BASE_PORT
        }
        nginxentry = OSIRIS_NGINX_ENTRY.format(**nginx_params)

        code, stdout = self.ssh("cat >> {}/config/osiris-instances.ini".format(self.nginx_root),_in=nginxentry)

        print ' > generating init.d script'
        # Configure startup script
        initd_params = {
            'port_index': port_index,
            'instance_folder': new_instance_folder
        }
        initd_script = INIT_D_SCRIPT.format(**initd_params)
        code, stdout = self.ssh("cat > /etc/init.d/oauth_{}".format(instance_name),_in=initd_script)
        if code != 0:
            return None
        code, stdout = self.ssh("chmod +x /etc/init.d/oauth_{}".format(instance_name))
        if code != 0:
            return None
        code, stdout = self.ssh("update-rc.d oauth_{} defaults".format(instance_name))
        if code != 0:
            return None

        print ' > executing buildout'
        # Execute buildout
        code, stdout = self.ssh('cd {} && ./bin/buildout -c osiris-only.cfg'.format(
            new_instance_folder)
        )  

        if code != 0:
            return None

