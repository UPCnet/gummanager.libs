"""UTalk Websocket client

Usage:
    utalk <maxserver> <username>

Options:
"""

import gevent
from gevent.event import AsyncResult
from gummanager.libs.utils import padded_error, padded_success, progress_log, padded_log
from gummanager.libs.utils import admin_password_for_branch, step_log, StepError, error_log
from gummanager.libs.utils import ReadyCounter, success_log, RemoteConnection
from gummanager.libs.config_files import MAXBUNNY_INSTANCE_ENTRY
from gummanager.libs.mixins import TokenHelper
from utalkpythonclient.testclient import UTalkTestClient


class UTalkServer(TokenHelper, object):

    def __init__(self, config, *args, **kwargs):
        self.config = config
        self.remote = RemoteConnection(self.config.maxbunny.ssh_user, self.config.maxbunny.server)

    def getDomainInfo(self, domain):
        max_info = self.config.max.get_instance(domain)
        oauth_info = self.config.oauth.instance_by_dns(max_info['oauth'])
        return {
            'max': max_info,
            'oauth': oauth_info
        }

    def getUtalkClient(self, maxserver, username, password, quiet=False):
        client = UTalkTestClient(
            maxserver=maxserver,
            username=username,
            password=password,
            quiet=quiet
        )
        return client

    def add_entry(self, configuration):
        instances_file = ''
        if self.remote.file_exists(self.config.maxbunny.instances_list):
            instances_file = self.remote.get_file(self.config.maxbunny.instances_list, do_raise=True)
        if '[{name}]'.format(**configuration) not in instances_file:
            linebreak = '\n' if instances_file else ''
            instances_file += linebreak + MAXBUNNY_INSTANCE_ENTRY.format(**configuration)
            self.remote.put_file(self.config.maxbunny.instances_list, instances_file, do_raise=True)
        else:
            return success_log("Instance {name} already in maxbunny instance list".format(**configuration))

        return success_log("Succesfully added {name} to maxbunny instance list".format(**configuration))

    def add_instance(self, **configuration):
        domain_info = self.getDomainInfo(configuration['name'])
        ldap_branch = domain_info['oauth']['ldap']['branch']
        configuration['restricted_user_token'] = 'aaa'

        self.get_token(
            configuration['oauth_server'],
            configuration['restricted_user'],
            admin_password_for_branch(ldap_branch)
        )

        try:
            yield step_log('Adding entry')
            yield self.add_entry(configuration)

        except StepError as error:
            yield error_log(error.message)

    def test(self, domain):
        progress_log('Testing UTalk websocket communication')

        # Get a maxclient for this instance
        padded_log("Getting instance information")

        domain_info = self.getDomainInfo(domain)
        restricted_password = admin_password_for_branch(domain_info['oauth']['ldap']['branch'])
        client = self.config.max.get_client(domain, username='restricted', password=restricted_password)

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
            max_clients.append(self.config.max.get_client(
                domain,
                username=user,
                password=password)
            )

            # Create websocket clients
            utalk_clients.append(self.getUtalkClient(
                domain_info['max']['server']['dns'],
                user,
                password,
                quiet=True
            ))
            counter.add()

        # Create users
        padded_log("Creating users and conversations")
        client.people['ulearn.testuser1'].post()
        client.people['ulearn.testuser2'].post()

        # user 1 creates conversation with user 2
        conversation = max_clients[0].conversations.post(
            contexts=[{"objectType": "conversation", "participants": [test_users[0][0], test_users[1][0]]}],
            object_content='Initial message'
        )
        conversation_id = conversation['contexts'][0]['id']

        # Prepare test messages for clients
        # First argument are messages to send (conversation, message)
        # Second argument are messages to expect (conversation, sender, message)
        # Third argument is a syncronization event to wait for all clients to be listening

        arguments1 = [
            [
                (conversation_id, 'First message from 1'),
                (conversation_id, 'Second message from 1')
            ],
            [
                (conversation_id, test_users[1][0], 'First message from 2'),
                (conversation_id, test_users[1][0], 'Second message from 2')
            ],
            counter,
        ]

        arguments2 = [
            [
                (conversation_id, 'First message from 2'),
                (conversation_id, 'Second message from 2')
            ],
            [
                (conversation_id, test_users[0][0], 'First message from 1'),
                (conversation_id, test_users[0][0], 'Second message from 1')
            ],
            counter
        ]

        padded_log("Starting websockets and waiting for messages . . .")

        utalk_clients[0].setup(*arguments1)
        utalk_clients[1].setup(*arguments2)

        greenlets = [
            gevent.spawn(utalk_clients[0].connect),
            gevent.spawn(utalk_clients[1].connect)
        ]

        gevent.joinall(greenlets, timeout=60, raise_error=True)
        success = None not in [g.value for g in greenlets]

        utalk_clients[0].teardown()
        utalk_clients[1].teardown()

        # Cleanup
        max_clients[0].conversations[conversation_id].delete()

        #client.people['ulearn.testuser1'].delete()
        #client.people['ulearn.testuser2'].delete()

        if success:
            padded_success('Websocket test passed')
        else:
            padded_error('Websocket test failed, Timed out')
