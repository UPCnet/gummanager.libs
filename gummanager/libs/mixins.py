import requests
import json

from gummanager.libs.supervisor import SupervisorControl
from gummanager.libs.utils import progress_log
from gummanager.libs.utils import padded_error
from gummanager.libs.utils import padded_log
from gummanager.libs.utils import padded_success
from gummanager.libs.utils import error_log
from gummanager.libs.utils import success_log

from time import sleep
from collections import OrderedDict


class TokenHelper(object):

    @staticmethod
    def get_token(oauth_server, username, password):
        payload = {"grant_type": 'password',
                   "client_id": 'MAX',
                   "scope": 'widgetcli',
                   "username": username,
                   "password": password
                   }

        req = requests.post('{0}/token'.format(oauth_server), data=payload, verify=False)
        response = json.loads(req.text)
        if req.status_code == 200:
            token = response.get("access_token")
            return token
        else:
            return None

    @staticmethod
    def check_token(oauth_server, username, token):
        payload = {
            "access_token": token,
            "username": username,
            "scope": 'widgetcli',
            "grant_type": 'password'
        }
        req = requests.post('{0}/checktoken'.format(oauth_server), data=payload, verify=False)
        return req.status_code == 200

    @staticmethod
    def oauth_headers(username, token):
        """
        """
        headers = {
            'X-Oauth-Token': token,
            'X-Oauth-Username': username,
            'X-Oauth-Scope': "widgetcli"
        }
        return headers


class ProcessHelper(object):
    """
        Methods related to starting, stopping and loading
        supervisor processes. Also does nginx reloading
    """

    def process_name(self, instance_name):
        return self.process_prefix + instance_name

    def get_status(self, instance_name):
        process_name = self.process_name(instance_name)
        supervisor = SupervisorControl(self.config)

        status = supervisor.status(process_name)
        result_status = OrderedDict()
        result_status['name'] = instance_name
        result_status['server'] = 'http://{}:{}'.format(self.config.server, self.config.supervisor.port)
        result_status['status'] = status['status'].lower()
        result_status['pid'] = status['pid']
        result_status['uptime'] = status['uptime']
        return result_status

    def start(self, instance_name):
        progress_log('Starting instance')
        status = self.get_status(instance_name)

        process_name = self.process_name(instance_name)
        supervisor = SupervisorControl(self.config)

        if status['status'] == 'unknown':
            padded_log('Unknown {} status ...')
        elif status['status'] == 'not found':
            supervisor.load(process_name)
        else:
            padded_log('Process stopped, starting ...')
            supervisor.start(process_name)

        padded_log('Waiting for process "{}" to start...'.format(process_name))

        retries = 10
        status = self.get_status(instance_name)

        while retries > 0 or status['status'] != 'running':
            sleep(1)
            status = self.get_status(instance_name)
            retries -= 1

        if status['status'] == 'running':
            padded_success('Process "{}" started'.format(process_name))
        elif status['status'] in ['fatal', 'backoff']:
            padded_error('Process "{}" not started, an error occurred'.format(process_name))
        else:
            padded_error('Process "{}" not started'.format(process_name))

    def stop(self, instance_name):
        progress_log('Stopping instance')

        process_name = self.process_name(instance_name)
        supervisor = SupervisorControl(self.config)

        supervisor.stop(process_name)

        padded_log('Waiting for "{}" instance to stop...'.format(instance_name))

        retries = 10
        status = self.get_status(instance_name)

        while retries > 0 or status['status'] != 'stopped':
            sleep(1)
            status = self.get_status(instance_name)
            retries -= 1

        status = self.get_status(instance_name)
        if status['status'].lower() == 'stopped':
            padded_success('Instance "{}" stopped'.format(instance_name))
        else:
            padded_error('Instance "{}" still active'.format(instance_name))

    def test_nginx(self):
        code, stdout = self.remote.execute('/etc/init.d/nginx configtest')
        if code == 0 and 'done' in stdout:
            return success_log('Configuration test passed')
        else:
            return error_log('Configuration test failed')

    def reload_nginx(self):
        code, stdout = self.remote.execute('/etc/init.d/nginx reload')
        if code == 0 and 'done' in stdout:
            return success_log('Nginx reloaded succesfully')
        else:
            return error_log('Error reloading nginx')
