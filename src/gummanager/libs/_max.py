from collections import OrderedDict
from gummanager.libs.buildout import RemoteBuildoutHelper
from gummanager.libs.config_files import INIT_D_SCRIPT
from gummanager.libs.config_files import MAX_NGINX_ENTRY
from gummanager.libs.config_files import CIRCUS_NGINX_ENTRY
from gummanager.libs.ports import BIGMAX_BASE_PORT
from gummanager.libs.ports import CIRCUS_HTTPD_BASE_PORT
from gummanager.libs.ports import CIRCUS_TCP_BASE_PORT
from gummanager.libs.ports import CIRCUS_NGINX_BASE_PORT
from gummanager.libs.ports import MAX_BASE_PORT
from gummanager.libs.utils import padded_error, padded_log
from gummanager.libs.utils import padded_success
from gummanager.libs.utils import RemoteConnection
from gummanager.libs.utils import circus_status, circus_control
from gummanager.libs.utils import parse_ini_from
from gummanager.libs.utils import progress_log
from gummanager.libs.utils import admin_password_for_branch


from maxclient.rest import MaxClient
from time import sleep
import pymongo
import gevent
from gevent.event import AsyncResult


class MaxServer(object):

    def __init__(self, *args, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

        self._client = None
        self._instances = {}
        self.remote = RemoteConnection(self.ssh_user, self.server)
        self.buildout = RemoteBuildoutHelper(self.remote, self.python_interpreter, self)

    def get_client(self, instance_name, username, password):
        instance_info = self.get_instance(instance_name)
        client = MaxClient(instance_info['server']['dns'])
        client.login(username=username, password=password)
        return client

    def get_instances(self):
        instances = []
        for instance_name in self.buildout.config_files:
            instance = self.get_instance(instance_name)
            if instance:
                instances.append(instance)
        return instances

    def set_mongodb_indexes(self, instance_name):
        new_instance_folder = '{}/{}'.format(
            self.instances_root,
            instance_name
        )
        code, stdout = self.remote.execute('{0}/bin/max.mongoindexes -c {0}/config/max.ini -i {0}/config/mongodb.indexes'.format(new_instance_folder))
        return 'Added' in stdout

    def configure_max_security_settings(self, instance_name):
        try:
            new_instance_folder = '{}/{}'.format(
                self.instances_root,
                instance_name
            )

            self.buildout.folder = new_instance_folder

            users = self.authorized_users
            default_security = {'roles': {"Manager": users}}
            hosts = self.mongodb_cluster
            replica_set = self.buildout.config_files['max.ini']['mongodb.replica_set']
            conn = pymongo.MongoReplicaSetClient(hosts, replicaSet=replica_set)

            db_name = self.buildout.config_files['max.ini']['mongodb.db_name']
            db = conn[db_name]

            if not [items for items in db.security.find({})]:
                db.security.insert(default_security)
        except:
            return None
        return True

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

        if status['status']['max'] == 'unknown':
            padded_log('Circus stopped, starting circusd ...')
            code, stdout = self.remote.execute('/etc/init.d/max_{} start'.format(instance_name))
        elif status['status']['max'] == 'stopped':
            padded_log('Osiris stopped, starting process ...')
            circus_control(
                'start',
                endpoint=instance['circus_tcp'],
                process='osiris'
            )

        padded_log('Waiting for circus...')
        sleep(1)
        status = self.get_status(instance_name)
        if status['status']['max'] == 'active':
            padded_success('Max instance {} started'.format(instance_name))
        else:
            padded_error('Max instance {} not started'.format(instance_name))

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
            padded_success('Osiris Max instance {} stopped'.format(instance_name))
        else:
            padded_error('Osiris Max instance {} still active'.format(instance_name))

    def test_activity(self, instance_name, ldap_branch):

        progress_log('Testing UTalk activity notifications')

        # Get a maxclient for this instance
        padded_log("Getting instance information")
        instance_info = self.get_instance(instance_name)
        restricted_password = admin_password_for_branch(ldap_branch)
        client = self.get_client(instance_name, username='restricted', password=restricted_password)

        padded_log("Setting up test clients")
        test_users = [
            ('ulearn.testuser1', 'UTestuser1'),
            ('ulearn.testuser2', 'UTestuser2')
        ]

        utalk_clients = []
        max_clients = []

        # Syncronization primitives
        wait_for_others = AsyncResult()
        counter = ReadyCounter(wait_for_others)

        for user, password in test_users:
            max_clients.append(self.get_client(
                instance_name,
                username=user,
                password=password)
            )

            # Create websocket clients
            utalk_clients.append(getUtalkClient(
                instance_info['server']['dns'],
                instance_name,
                user,
                password,
                quiet=False
            ))
            counter.add()

        # Create users
        padded_log("Creating users and conversations")
        client.people['ulearn.testuser1'].post()
        client.people['ulearn.testuser2'].post()

        # Admin creates context with notifications enabled and subscribes users to it
        context = client.contexts.post(url='http://testcontext', displayName='Test Context', notifications=True)
        client.people['ulearn.testuser1'].subscriptions.post(object_url='http://testcontext')
        client.people['ulearn.testuser2'].subscriptions.post(object_url='http://testcontext')

        def post_activity():
            max_clients[0].people['ulearn.testuser1'].activities.post(
                object_content='Hola',
                contexts=[{"url": "http://testcontext", "objectType": "context"}]
            )

        # Prepare test messages for clients
        # First argument are messages to send (conversation, message)
        # Second argument are messages to expect (conversation, sender, message)
        # Third argument is a syncronization event to wait for all clients to be listening
        # Fourth argument is a method to trigger when client ready

        arguments1 = [
            [

            ],
            [
                ('test', 'test')
            ],
            counter,
            post_activity
        ]

        arguments2 = [
            [

            ],
            [
                ('test', 'test')
            ],
            counter,
            None
        ]

        padded_log("Starting websockets and waiting for messages . . .")

        greenlets = [
            gevent.spawn(utalk_clients[0].test, *arguments1),
            gevent.spawn(utalk_clients[1].test, *arguments2)
        ]

        gevent.joinall(greenlets, timeout=20, raise_error=True)

        success = None not in [g.value for g in greenlets]

        if success:
            padded_success('Websocket test passed')
        else:
            padded_error('Websocket test failed, Timed out')


    def get_status(self, instance_name):
        instance = self.get_instance(instance_name)
        max_status = circus_status(
            endpoint=instance['circus_tcp'],
            process='max'
        )

        result_status = OrderedDict()
        result_status['name'] = instance_name
        result_status['server'] = instance['server']
        result_status['status'] = {
            'max': max_status['status'],
        }
        result_status['pid'] = {
            'max': max_status['pid'],
        }

        result_status['uptime'] = {
            'max': max_status['uptime'],
        }

        return result_status

    def get_instance(self, instance_name):
        if instance_name not in self._instances:
            max_ini = self.buildout.config_files.get(instance_name, {}).get('max.ini', '')
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

            self._instances[instance_name] = instance
        return self._instances[instance_name]

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
            'max-config': {
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

        progress_log('Creating nginx entry for max')
        nginx_params = {
            'instance_name': instance_name,
            'server_dns': self.server_dns,
            'bigmax_port': BIGMAX_BASE_PORT,
            'max_port': int(port_index) + MAX_BASE_PORT
        }
        nginxentry = MAX_NGINX_ENTRY.format(**nginx_params)

        success = self.remote.put_file("{}/config/max-instances/{}.conf".format(self.nginx_root, instance_name), nginxentry)

        if success:
            padded_success("Succesfully created {}/config/max-instances/{}.conf".format(self.nginx_root, instance_name))
        else:
            padded_error('Error when generating nginx config file for max')
            return None

        ###########################################################################################

        progress_log('Creating nginx entry for circus')
        circus_nginx_params = {
            'circus_nginx_port': int(port_index) + CIRCUS_NGINX_BASE_PORT,
            'circus_httpd_endpoint': int(port_index) + CIRCUS_HTTPD_BASE_PORT
        }
        circus_nginxentry = CIRCUS_NGINX_ENTRY.format(**circus_nginx_params)

        success = self.remote.put_file("{}/config/circus-instances/{}.conf".format(self.nginx_root, instance_name), circus_nginxentry)

        if success:
            padded_success("Succesfully created {}/config/circus-instances/{}.conf".format(self.nginx_root, instance_name))
        else:
            padded_error('Error when generating nginx config file for circus')
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
            padded_success("Succesfully created a new max instance")
        else:
            padded_error("Error on buildout execution")
            return None

        ###########################################################################################

        progress_log('Adding indexes to mongodb')

        success = self.set_mongodb_indexes(instance_name)
        if success:
            padded_success("Succesfully added indexes")
            return None
        else:
            padded_error("Error on adding indexes")

        ###########################################################################################

        progress_log('Changing permissions')

        success = self.buildout.change_permissions(self.process_uid)
        if success:
            padded_success("Succesfully changed permissions")
            return None
        else:
            padded_error("Error on changing permissions")

        ###########################################################################################

        progress_log('Configuring default permissions settings')

        success = self.configure_max_security_settings(instance_name)
        if success:
            padded_success("Succesfully changed permissions settings")
            return None
        else:
            padded_error("Error on setting permissions settings")
