import requests
import json

from gummanager.libs.supervisor import SupervisorControl
from gummanager.libs.utils import progress_log
from gummanager.libs.utils import padded_error
from gummanager.libs.utils import skippable_error_log
from gummanager.libs.utils import padded_log
from gummanager.libs.utils import padded_success
from gummanager.libs.utils import error_log
from gummanager.libs.utils import success_log
from gummanager.libs.utils import success
from gummanager.libs.utils import step_log
from gummanager.libs.utils import message_log
from gummanager.libs.utils import StepError
from gummanager.libs.utils import configure_ini
from gummanager.libs.utils import command


from time import sleep
from collections import OrderedDict


class CommonSteps(object):

    def clone_buildout(self):

        if self.remote.file_exists('{}'.format(self.buildout.folder)):
            return skippable_error_log('Folder {} already exists'.format(self.buildout.folder))

        return success(
            self.buildout.clone(self.config.maxserver_buildout_uri, self.config.maxserver_buildout_branch),
            'Succesfully cloned repo at {}'.format(self.buildout.folder)
        )

    def bootstrap_buildout(self):
        return success(
            self.buildout.bootstrap(),
            'Succesfully bootstraped buildout {}'.format(self.buildout.folder)
        )

    def execute_buildout(self, update=False):
        self.buildout.execute(update=update)
        return success_log("Succesfully executed {} buildout".format(self.buildout.cfgfile))

    def configure_mongoauth(self):

        customizations = {
            'mongo-auth': {
                'authdb': self.config.mongodb.authdb,
                'username': self.config.mongodb.username,
                'password': self.config.mongodb.password
            },
        }

        self.buildout.configure_file('mongoauth.cfg', customizations),
        return success_log('Succesfully configured {}/mongoauth.cfg'.format(self.buildout.folder))

    def set_filesystem_permissions(self):
        self.buildout.change_permissions(self.config.process_uid)
        return success_log("Succesfully changed permissions")

    def configure_supervisor(self):
        new_instance_folder = '{}/{}'.format(
            self.config.instances_root,
            self.instance.name
        )

        settings = {
            'supervisor': {'parts': [new_instance_folder]}
        }

        remote_file = "{}/customizeme.cfg".format(self.config.supervisor.path)
        customizeme = configure_ini(
            string=self.remote.get_file(remote_file),
            append=True,
            params=settings)

        successfull = self.remote.put_file("{}/{}".format(self.config.supervisor.path, 'customizeme.cfg'), customizeme)
        if not successfull:
            raise StepError('Error when configuring {}'.format(remote_file))

        code, stdout = self.remote.execute('cd {} && ./supervisor_config'.format(self.config.supervisor.path), do_raise=True)

        return success(
            stdout,
            "Succesfully added {} to supervisor".format(new_instance_folder)
        )


class TokenHelper(object):

    @staticmethod
    def get_token(oauth_server, username, password):
        payload = {"grant_type": 'password',
                   "scope": 'widgetcli',
                   "username": username,
                   "password": password
                   }

        req = requests.post(
            '{0}/token'.format(oauth_server),
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'},
            verify=False)
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
        req = requests.post(
            '{0}/checktoken'.format(oauth_server),
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'},
            verify=False)
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


class SupervisorHelpers(object):
    """
        Methods related to starting, stopping and loading
        supervisor processes.
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

    def start(self, instance_name, padded=False):
        if not padded:
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
            sleep(0.5)
            status = self.get_status(instance_name)
            retries -= 1

        if status['status'] == 'running':
            padded_success('Process "{}" started'.format(process_name))
            return True
        elif status['status'] in ['fatal', 'backoff']:
            padded_error('Process "{}" not started, an error occurred'.format(process_name))
            return False
        else:
            padded_error('Process "{}" not started'.format(process_name))
            return False

    def stop(self, instance_name, padded=False):
        if not padded:
            progress_log('Stopping instance')

        process_name = self.process_name(instance_name)
        supervisor = SupervisorControl(self.config)

        supervisor.stop(process_name)

        padded_log('Waiting for "{}" instance to stop...'.format(instance_name))

        retries = 10
        status = self.get_status(instance_name)

        while retries > 0 or status['status'] != 'stopped':
            sleep(0.5)
            status = self.get_status(instance_name)
            retries -= 1

        status = self.get_status(instance_name)
        if status['status'].lower() == 'stopped':
            padded_success('Instance "{}" stopped'.format(instance_name))
            return True
        else:
            padded_error('Instance "{}" still active'.format(instance_name))
            return False

    def restart(self, instance_name):
        progress_log('Restarting instance')

        stop_result = self.stop(instance_name, padded=True)
        if stop_result is True:
            start_result = self.start(instance_name, padded=True)

        if start_result is True:
            padded_log('Instance "{}" restarted'.format(instance_name))
        else:
            padded_error('Instance "{}" not restarted'.format(instance_name))


class NginxHelpers(object):
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

    @command
    def reload_nginx_configuration(self):
        yield step_log('Reloading nginx configuration')
        yield message_log('Testing configuration')

        yield self.test_nginx()
        yield self.reload_nginx()
