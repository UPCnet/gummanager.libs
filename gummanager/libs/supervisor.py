import xmlrpclib
from gummanager.libs.utils import padded_log, padded_error
from socket import error as SocketError

import humanize
import datetime
import sys


def check_supervisor(func):
    def inner(self, instance_name):
        try:
            return func(self, instance_name)
        except SocketError as exc:
            if exc.errno == 111:
                padded_error('WARNING! Supervisord process not running')
            return {
                'pid': 'unknown',
                'status': 'down',
                'uptime': 'unknown'
            }
    return inner


class SupervisorControl(object):
    def __init__(self, config):
        uri = 'http://admin:{}@{}:{}/RPC2'.format(
            config.supervisor.password,
            config.server,
            config.supervisor.port)
        self.server = xmlrpclib.Server(uri)

    @check_supervisor
    def status(self, instance_name):
        default = {
            'pid': 'unknown',
            'status': 'unknown',
            'uptime': 'unknown'
        }

        try:
            process_info = self.server.supervisor.getProcessInfo(instance_name)
        except xmlrpclib.Fault as exc:
            if exc.faultCode == 10:
                default['status'] = 'not found'
        else:
            default['status'] = process_info['statename'].lower()
            default['pid'] = process_info['pid']
            start_date = datetime.datetime.fromtimestamp(process_info['start'])
            default['uptime'] = humanize.naturaltime(start_date)

        return default

    @check_supervisor
    def start(self, instance_name):
        self.server.supervisor.startProcess(instance_name)

    @check_supervisor
    def stop(self, instance_name):
        self.server.supervisor.stopProcess(instance_name)

    @check_supervisor
    def load(self, instance_name):
        loaded = self.server.supervisor.reloadConfig()
        loaded_instances = loaded[0][0]
        padded_log('New instances found: {}'.format(', '.join(loaded_instances)))
        if instance_name in loaded_instances:
            self.server.supervisor.addProcessGroup(instance_name)
        else:
            padded_error('No instance named "{}" found after reloading configuration'.format(instance_name))
            sys.exit(1)
