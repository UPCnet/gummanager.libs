# -*- coding: utf-8 -*-
from maxclient.rest import MaxClient
from maxutils.mongodb import get_connection
from maxutils.mongodb import get_database

from collections import OrderedDict
from gevent.event import AsyncResult
from gummanager.libs.buildout import RemoteBuildoutHelper
from gummanager.libs.config_files import BIGMAX_INSTANCE_ENTRY
from gummanager.libs.config_files import MAX_NGINX_ENTRY
from gummanager.libs.mixins import CommonSteps
from gummanager.libs.mixins import NginxHelpers
from gummanager.libs.mixins import SupervisorHelpers
from gummanager.libs.ports import BIGMAX_BASE_PORT
from gummanager.libs.ports import MAX_BASE_PORT
from gummanager.libs.pyramid import PyramidServer
from gummanager.libs.utils import RemoteConnection
from gummanager.libs.utils import admin_password_for_branch
from gummanager.libs.utils import command
from gummanager.libs.utils import error_log
from gummanager.libs.utils import padded_error
from gummanager.libs.utils import padded_log
from gummanager.libs.utils import padded_success
from gummanager.libs.utils import parse_ini_from
from gummanager.libs.utils import progress_log
from gummanager.libs.utils import step_log
from gummanager.libs.utils import success
from gummanager.libs.utils import success_log
from time import sleep

import gevent
import re
import requests


class MaxServer(SupervisorHelpers, NginxHelpers, CommonSteps, PyramidServer):

    def __init__(self, config, *args, **kwargs):
        self.config = config

        self.process_prefix = 'max_'
        self._client = None
        self._instances = {}
        self.instance = None
        self.remote = RemoteConnection(self.config.ssh_user, self.config.server)
        self.buildout = RemoteBuildoutHelper(self.remote, self.config.python_interpreter, self)

        if not self.remote.file_exists(self.config.instances_root):
            self.remote.mkdir(self.config.instances_root)

    def get_client(self, instance_name, username='', password=''):
        instance_info = self.get_instance(instance_name)
        client = MaxClient(instance_info['server']['dns'])
        if username and password:
            client.login(username=username, password=password)
        return client

    def get_running_version(self, instance_name):
        instance_info = self.get_instance(instance_name)
        return requests.get('{}/info'.format(instance_info['server']['dns'])).json().get('version', '???')

    def get_expected_version(self, instance_name):
        versions = self.remote.get_file('{}/versions.cfg'.format(self.buildout.folder))
        return re.search(r'\smax\s=\s(.*?)\s', versions, re.MULTILINE).groups()[0]

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
                'direct': 'http://{}:{}'.format(self.config.server, maxconfig['server:main']['port']),
                'dns': maxconfig['app:main']['max.server']
            }
            instance['oauth'] = maxconfig['app:main']['max.oauth_server']
            self._instances[instance_name] = instance
        return self._instances[instance_name]

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

    # Steps used in commands. Some of them defined in gummanager.libs.mixins

    def configure_instance(self):

        customizations = {
            'mongodb-config': {
                'replica_set': self.config.mongodb.replica_set,
                'cluster_hosts': self.config.mongodb.cluster
            },
            'max-config': {
                'name': self.instance.name,
            },
            'ports': {
                'port_index': '{:0>2}'.format(self.instance.index),
            },
            'rabbitmq-config': {
                'username': self.config.rabbitmq.username,
                'password': self.config.rabbitmq.password
            },
            'hosts': {
                'max': self.config.server_dns,
                'oauth': self.config.oauth.server_dns,
                'rabbitmq': self.config.rabbitmq.server

            }
        }

        self.buildout.configure_file('customizeme.cfg', customizations),
        return success_log('Succesfully configured {}/customizeme.cfg'.format(self.buildout.folder))

    def set_mongodb_indexes(self):
        new_instance_folder = '{}/{}'.format(
            self.config.instances_root,
            self.instance.name
        )
        code, stdout = self.remote.execute('cd {0} && ./bin/max.mongoindexes'.format(new_instance_folder))
        added = 'Added' in stdout

        if added:
            return success_log("Succesfully added indexes")
        else:
            return error_log("Error on adding indexes")

    def configure_max_security_settings(self):
        try:
            new_instance_folder = '{}/{}'.format(
                self.config.instances_root,
                self.instance.name
            )
            self.buildout.folder = new_instance_folder

            # Force read the new configuration files
            self.buildout.reload()
            maxini = self.buildout.config_files[self.instance.name]['max.ini']
            maxconfig = parse_ini_from(maxini)
            users = self.config.authorized_users
            default_security = {'roles': {"Manager": users}}
            hosts = self.config.mongodb.cluster
            replica_set = self.config.mongodb.replica_set
            conn = get_connection(hosts, replica_set)
            db_name = maxconfig['app:main']['mongodb.db_name']
            password = self.config.mongodb.password
            db = get_database(conn, db_name, username=self.config.mongodb.username, password=password, authdb=self.config.mongodb.authdb)

            if not [items for items in db.security.find({})]:
                db.security.insert(default_security)
        except:
            return error_log("Error on setting permissions settings")
        return success_log("Succesfully changed permissions settings")

    def create_max_nginx_entry(self):

        nginx_params = {
            'instance_name': self.instance.name,
            'server_dns': self.config.server_dns,
            'bigmax_port': BIGMAX_BASE_PORT,
            'max_port': int(self.instance.index) + MAX_BASE_PORT
        }
        nginxentry = MAX_NGINX_ENTRY.format(**nginx_params)

        nginx_file_location = "{}/config/max-instances/{}.conf".format(self.config.nginx_root, self.instance.name)
        self.remote.put_file(nginx_file_location, nginxentry)
        return success_log("Succesfully created {}".format(nginx_file_location))

    def commit_local_changes(self):
        self.buildout.commit_to_local_branch(
            self.config.local_git_branch,
            files=[
                'customizeme.cfg',
                'mongoauth.cfg'
            ])
        return success_log("Succesfully commited local changes")

    def add_instance_to_bigmax(self):
        instances_file = ''
        if self.remote.file_exists(self.config.bigmax_instances_list):
            instances_file = self.remote.get_file(self.config.bigmax_instances_list, do_raise=True)
        if '[{}]'.format(self.instance.name) not in instances_file:
            linebreak = '\n' if instances_file else ''
            instances_file += linebreak + BIGMAX_INSTANCE_ENTRY.format(**{
                "server_dns": self.config.server_dns,
                "instance_name": self.instance.name,
            })
            self.remote.put_file(self.config.bigmax_instances_list, instances_file, do_raise=True)
        else:
            return success_log("Instance {} already in bigmax instance list".format(self.instance.name))

        return success_log("Succesfully added {} to bigmax instance list".format(self.instance.name))

    def update_buildout(self):
        result = self.buildout.upgrade('master', self.config.local_git_branch)
        return success(result, "Succesfully commited local changes")

    def reload_instance(self):
        self.reload(self.instance.name, 'max')
        sleep(1)
        status = self.get_status(self.instance.name)
        if status['status'] == 'running':
            return success_log("Succesfully restarted max {}".format(self.instance.name))
        else:
            return error_log('Max instance {} is not running'.format(self.instance.name))

    def check_version(self):
        running_version = self.get_running_version(self.instance.name)
        expected_version = self.get_expected_version(self.instance.name)

        if running_version == expected_version:
            return success_log("Max {} is running on {}".format(self.instance.name, running_version))
        else:
            return success_log("Max {} is running on {}, but {} was expected".format(self.instance.name, running_version, expected_version))

    # Commands

    @command
    def new_instance(self, instance_name, port_index, oauth_instance=None, logecho=None, rabbitmq_url=None):

        self.buildout.cfgfile = self.config.max.cfg_file
        self.buildout.logecho = logecho
        self.buildout.folder = '{}/{}'.format(
            self.config.instances_root,
            instance_name
        )

        self.set_instance(
            name=instance_name,
            index=port_index,
            oauth=oauth_instance if oauth_instance is not None else instance_name,
        )

        yield step_log('Cloning buildout')
        yield self.clone_buildout()

        yield step_log('Bootstraping buildout')
        yield self.bootstrap_buildout()

        yield step_log('Configuring customizeme.cfg')
        yield self.configure_instance()

        yield step_log('Configuring mongoauth.cfg')
        yield self.configure_mongoauth()

        yield step_log('Executing buildout')
        yield self.execute_buildout()

        yield step_log('Adding indexes to mongodb')
        yield self.set_mongodb_indexes()

        yield step_log('Configuring default permissions settings')
        yield self.configure_max_security_settings()

        yield step_log('Creating nginx entry for max')
        yield self.create_max_nginx_entry()

        yield step_log('Commiting to local branch')
        yield self.commit_local_changes()

        yield step_log('Changing permissions')
        yield self.set_filesystem_permissions()

        yield step_log('Adding instance to supervisor config')
        yield self.configure_supervisor()

        yield step_log('Adding instance to bigmax')
        yield self.add_instance_to_bigmax()

    @command
    def upgrade(self, instance_name, logecho=None):
        self.buildout.cfgfile = self.config.max.cfg_file
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

        yield step_log('Reloading max')
        yield self.reload_instance()

        yield step_log('Checking running version')
        yield self.check_version()
