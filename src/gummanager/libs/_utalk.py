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


def random_str(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for c in range(length))


def forge_message(command, headers, body):
    frame = Frame(command, headers, body)
    message = convert_frame_to_lines(frame)
    return '["' + ''.join(message[:-1]) + '"]'


class StompClient(object):
    def __init__(self, username, passcode, sockjs_client):
        self.username = username
        self.passcode = passcode
        self.sockjs = sockjs_client

    @property
    def ws(self):
        return self.sockjs.ws

    def connect(self):
        headers = OrderedDict()
        headers["login"] = self.username
        headers["passcode"] = self.passcode
        headers["host"] = "/"
        headers["accept-version"] = "1.1,1.0"
        headers["heart-beat"] = "0,0"

        message = forge_message('CONNECT', headers, '\u0000')
        self.ws.send(message)
        print '> Started stomp session as {}'.format(self.username)

    def subscribe(self):
        headers = OrderedDict()
        headers["id"] = "sub-0",
        headers["destination"] = "/exchange/{}.subscribe".format(self.username),

        message = forge_message('SUBSCRIBE', headers, '\u0000')
        self.ws.send(message)
        print '> Listening on {} messages'.format(self.username)
        print

    def receive(self, headers, body):
        message = RabbitMessage.unpack(body)
        destination = re.search(r'([0-9a-f]+).(?:notifications|messages)', headers['destination']).groups()[0]
        if message['action'] == 'add' and message['object'] == 'message':
            print '> {}@{}: {}'.format(message['user']['username'], destination, message['data']['text'])


class UTalkClient(object):

    def __init__(self, host, username, passcode):
        self.host = host
        self.username = username
        self.passcode = passcode
        self.stomp = StompClient(username, passcode, self)

    def connect(self):
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
                decoded_message = json.loads(body.replace('\\"', '"').replace('\u0000', ''))
                self.stomp.receive(headers, decoded_message)

    def on_error(self, ws, error):
        print '> ERROR {}'.format(error)

    def on_close(self, ws):
        print "> Closed websocket connection"

    def on_open(self, ws):
        print '> Opened websocket connection to {}'.format(self.url)


def main(argv=sys.argv):

    def get_servers_from_max(maxserver):
        response = requests.get('{}/info'.format(maxserver), verify=False)
        oauth_server = response.json()['max.oauth_server']
        stomp_server = '{}/stomp'.format(maxserver.replace('http', 'ws'))
        return oauth_server, stomp_server

    def getToken(username, oauth_server):
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
