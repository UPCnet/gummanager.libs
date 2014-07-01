"""UTalk Websocket client

Usage:
    utalk <maxserver> <username>

Options:
"""

from docopt import docopt
import random
import string
import websocket
import re
from collections import OrderedDict
from stomp.utils import Frame, convert_frame_to_lines
import sys
from maxcarrot import RabbitMessage
import getpass
import requests
import json
import gevent
from gevent.monkey import patch_all


def random_str(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for c in range(length))


def get_servers_from_max(maxserver):
    response = requests.get('{}/info'.format(maxserver), verify=False)
    oauth_server = response.json()['max.oauth_server']
    stomp_server = '{}/stomp'.format(maxserver.replace('http', 'ws'))
    return oauth_server, stomp_server


def getToken(username, oauth_server, password=None):
    if password is None:
        print '> Enter password for user {}'.format(username)
        password = getpass.getpass()

    payload = {
        "grant_type": 'password',
        "client_id": 'MAX',
        "scope": 'widgetcli',
        "username": username,
        "password": password
    }
    req = requests.post('{0}/token'.format(oauth_server), data=payload, verify=False)
    response = json.loads(req.text)
    token = False
    if req.status_code == 200:
        token = response.get("access_token", False)
        # Fallback to legacy oauth server
        if not token:
            token = response.get("oauth_token")
    if token:
        return token
    else:
        print "Bad username or password."
        sys.exit(1)


def forge_message(command, headers, body=''):
    frame = Frame(command, headers, body)
    message = convert_frame_to_lines(frame)
    return '["' + ''.join(message[:-1]) + '\u0000"]'


class StompClient(object):
    def __init__(self, username, passcode, utalk_client, domain):
        self.username = username
        self.passcode = passcode
        self.utalk = utalk_client
        self.domain = domain

    @property
    def ws(self):
        return self.utalk.ws

    @property
    def log(self):
        return self.utalk.log

    def connect(self):
        headers = OrderedDict()
        headers["login"] = self.domain + ':' + self.username
        headers["passcode"] = self.passcode
        headers["host"] = "/"
        headers["accept-version"] = "1.1,1.0"
        headers["heart-beat"] = "0,0"
        message = forge_message('CONNECT', headers)
        self.ws.send(message)
        self.log('> Started stomp session as {}'.format(self.username))

    def subscribe(self):
        headers = OrderedDict()
        headers["id"] = "sub-0",
        headers["destination"] = "/exchange/{}.subscribe".format(self.username),

        message = forge_message('SUBSCRIBE', headers)
        self.ws.send(message)

        self.log('> Listening on {} messages'.format(self.username))
        self.utalk.wait_send.ready()
        gevent.sleep(1)
        self.utalk.wait_send.event.get()
        self.log("start sending {} messages".format(self.username))
        for conversation_id, text in self.utalk.to_send:
            self.utalk.send_message(conversation_id, text)

    def send(self, headers, body):
        message = forge_message('SEND', headers, body)
        self.ws.send(message)

    def receive(self, headers, body):
        message = RabbitMessage.unpack(body)
        #if message['action'] == 'add' and message['object'] == 'message':
        #    self.log('')


class UTalkClient(object):

    def __init__(self, host, username, passcode, domain, quiet=False):
        self.host = host
        self.username = username
        self.passcode = passcode
        self.stomp = StompClient(username, passcode, self, domain)
        self.domain = domain
        self.quiet = quiet

    def log(self, message):
        if not self.quiet:
            print message

    def connect(self):
        patch_all()
        self.url = '/'.join([
            self.host,
            str(random.randint(0, 1000)),
            random_str(8),
            'websocket'])
        self.ws = websocket.WebSocketApp(
            self.url,
            header={'Connection': 'Keep-Alive'},
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )
        self.ws.on_open = self.on_open
        self.ws.run_forever()

    def on_message(self, ws, message):
        if message[0] == 'o':
            self.stomp.connect()
        if message[0] == 'a':
            command, params, body = re.search(r'a\[\"(\w+)\\n(.*)\\n([^\n]+)"\]', message).groups()
            headers = dict(re.findall(r'([^:]+):(.*?)\\n?', params, re.DOTALL | re.MULTILINE))

            if command == 'CONNECTED':
                self.stomp.subscribe()

            if command == 'MESSAGE':
                self.received_messages += 1
                decoded_message = json.loads(body.replace('\\"', '"').replace('\u0000', ''))
                self.stomp.receive(headers, decoded_message)
                if self.received_messages == self.expected_messages:
                    self.ws.close()

    def send_message(self, conversation, text):
        message = RabbitMessage()
        message.prepare()
        message['source'] = 'test'
        message['data'] = {'text': text}
        message['action'] = 'add'
        message['object'] = 'message'
        message['user'] = {'username': self.username}

        headers = {
            "destination": "/exchange/{}.publish/{}.messages".format(self.username, conversation),
        }
        # Convert to json and strip  spaces
        json_message = json.dumps(message.packed, separators=(',', ':'))
        json_message = json_message.replace('"', '\\"')
        self.stomp.send(headers, json_message)

    def on_error(self, ws, error):
        self.log('> ERROR {}'.format(error))

    def on_close(self, ws):
        self.log("> Closed websocket connection")

    def on_open(self, ws):
        self.log('> Opened websocket connection to {}'.format(self.url))

    def test(self, send=[], expect=[], ready=None):
        self.to_send = send
        self.to_expect = expect
        self.wait_send = ready

        self.expected_messages = len(self.to_expect) + len(self.to_send) * 2
        self.received_messages = 0

        self.connect()
        return True


def main(argv=sys.argv):

    arguments = docopt(__doc__, version='UTalk websocket client 1.0')

    print
    print "  UTalk websocket client"
    print

    oauth_server, stomp_server = get_servers_from_max(arguments['<maxserver>'])
    token = getToken(arguments['<username>'], oauth_server)
    client = UTalkClient(
        host=stomp_server,
        username=arguments['<username>'],
        passcode=token
    )
    client.connect()
