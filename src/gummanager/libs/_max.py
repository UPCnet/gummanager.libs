from collections import OrderedDict
from gummanager.libs.buildout import RemoteBuildoutHelper
from gummanager.libs.config_files import INIT_D_SCRIPT
from gummanager.libs.config_files import MAX_NGINX_ENTRY
from gummanager.libs.ports import BIGMAX_BASE_PORT
from gummanager.libs.ports import CIRCUS_HTTPD_BASE_PORT
from gummanager.libs.ports import CIRCUS_TCP_BASE_PORT
from gummanager.libs.ports import MAX_BASE_PORT
from gummanager.libs.utils import padded_error, padded_log
from gummanager.libs.utils import padded_success
from gummanager.libs.utils import RemoteConnection
from gummanager.libs.utils import circus_status, circus_control
from gummanager.libs.utils import parse_ini_from
from gummanager.libs.utils import progress_log

from time import sleep


class MaxServer(object):

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
        max_status = circus_status(
            endpoint=instance['circus_tcp'],
            process='max'
        )
        bigmax_status = circus_status(
            endpoint=instance['circus_tcp'],
            process='bigmax'
        )

        result_status = OrderedDict()
        result_status['name'] = instance_name
        result_status['server'] = instance['server']
        result_status['status'] = {
            'max': max_status['status'],
            'bigmax': bigmax_status['status'],
        }
        result_status['pid'] = {
            'max': max_status['pid'],
            'bigmax': bigmax_status['pid'],
        }

        result_status['uptime'] = {
            'max': max_status['uptime'],
            'bigmax': bigmax_status['uptime'],
        }

        return result_status

    def get_instance(self, instance_name):
        max_ini = self.buildout.config_files[instance_name].get('max.ini', '')
        if not max_ini:
            return {}

        maxconfig = parse_ini_from(max_ini)
        port_index = int(maxconfig['server:main']['port']) - MAX_BASE_PORT

        instance = OrderedDict()
        instance['name'] = instance_name
        instance['port_index'] = port_index
        instance['mongo_database'] = maxconfig['app:main']['mongodb.db_name']
        instance['server'] = {
            'direct': 'http://{}:{}'.format(self.server, maxconfig['server:main']['port']),
            'dns': maxconfig['app:main']['max.server']
        }
        instance['oauth'] = maxconfig['app:main']['max.oauth_server']
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

    def new_instance(self, instance_name, port_index, oauth_instance=None):
        oauth_instance = oauth_instance if oauth_instance is not None else instance_name
        repo_url = 'https://github.com/UPCnet/maxserver'
        new_instance_folder = '{}/{}'.format(
            self.instances_root,
            instance_name
        )

        self.buildout.folder = new_instance_folder

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

        success = self.buildout.bootstrap('max-only.cfg')

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
                'port_index': '{:0>2}'.format(port_index),
            },
            'urls': {
                'oauth': 'https://{}/{}'.format(self.default_oauth_server_dns, oauth_instance)
            }

        }

        success = self.buildout.configure_file('customizeme.cfg', customizations)

        if success:
            padded_success('Succesfully configured {}/customizeme.cfg'.format(new_instance_folder))
        else:
            padded_error('Error on applying settings on customizeme.cfg')
            return None

        ###########################################################################################

        progress_log('Creating nginx entry')
        nginx_params = {
            'instance_name': instance_name,
            'server_dns': self.server_dns,
            'bigmax_port': int(port_index) + BIGMAX_BASE_PORT,
            'max_port': int(port_index) + MAX_BASE_PORT
        }
        nginxentry = MAX_NGINX_ENTRY.format(**nginx_params)

        success = self.remote.put_file("{}/config/max-instances/{}.conf".format(self.nginx_root, instance_name), nginxentry)

        if success:
            padded_success("Succesfully created {}/config/max-instances/{}.conf".format(self.nginx_root, instance_name))
        else:
            padded_error('Error when generating nginx config file')
            return None

        ###########################################################################################

        progress_log('Generating init.d script')
        initd_params = {
            'port_index': int(port_index) + CIRCUS_TCP_BASE_PORT,
            'instance_folder': new_instance_folder
        }
        initd_script = INIT_D_SCRIPT.format(**initd_params)
        success = self.remote.put_file("/etc/init.d/max_{}".format(instance_name), initd_script)

        code, stdout = self.remote.execute("chmod +x /etc/init.d/max_{}".format(instance_name))
        if code != 0:
            success = False

        code, stdout = self.remote.execute("update-rc.d max_{} defaults".format(instance_name))
        if code != 0:
            success = False

        if success:
            padded_success("Succesfully created /etc/init.d/max_{}".format(instance_name))
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
            padded_success("Succesfully created a new max instance")

        progress_log('Executing buildout')

        ###########################################################################################

        success = self.buildout.change_permissions(self.process_uid)
        if success:
            padded_error("Error on changing permissions")
            return None
        else:
            padded_success("Succesfully changed permissions")
