from sh import ssh, ErrorReturnCode
import requests
from StringIO import StringIO
from configobj import ConfigObj
from circus.client import CircusClient
import datetime
import humanize
import re
import sys
from blessings import Terminal
term = Terminal()

class RemoteConnection(object):
    def __init__(self, user, server):
        self.ssh = ssh.bake('{}@{}'.format(user, server))

    def execute(self, command, **kwargs):
        try:
            result = self.ssh(command, **kwargs)
        except:
            return None, ''

        return result.exit_code, result.stdout

    def file_exists(self, filename):
        try:
            result = self.ssh('ls {}'.format(filename))
        except ErrorReturnCode:
            return False
        return True

    def get_file(self, filename):
        try:
            result = self.ssh('cat {}'.format(filename))
        except ErrorReturnCode:
            return None
        return result.stdout

    def put_file(self, filename, content):
        try:
            result = self.ssh("cat > {}".format(filename),_in=content)
        except ErrorReturnCode:
            return None
        # if successfull check back content of file
        return self.get_file(filename) == content


def padded_success(string):
    print term.bold_green + '    {}'.format(string) + term.normal

def padded_error(string):
    print term.bold_red + '    {}\n'.format(string) + term.normal

def padded_log(string, filters=[]):
    string = string.rstrip()
    matched_filter = re.search(r'({})'.format('|'.join(filters)), string)
    do_print = matched_filter or filters == []
    # we have a multiline
    line = re.sub(r'([\n\r])', r'\1    ', string)
    if do_print:
        print '    ' + line.rstrip()


def progress_log(string):
    print
    print term.bold_cyan + '> {}'.format(string) + term.normal
    print


def parse_ini_from(string=None, filename=None, url=None, params={}):
    if url is not None:
        text = requests.get(url, verify=False).content
    elif filename is not None:
        text = open(filename).read()
    elif string is not None:
        text = string

    input_config = StringIO(text)
    return ConfigObj(input_config, encoding="utf-8", list_values=False)


def configure_ini(string=None, filename=None, url=None, params={}):

    config = parse_ini_from(string=string, filename=filename, url=url, params=params)
    for section_name, section_items in params.items():
        section = config[section_name]
        for element_name, value in section_items.items():
            section[element_name] = value

    out = StringIO()
    config.write(out)
    out.seek(0)
    return out.read().replace('"', '')


def circus_status(endpoint=None, process=None):
    default = {
        'pid': 'unknown',
        'status': 'unknown',
        'uptime': 'unknown'
    }

    if endpoint and process:
        client = CircusClient(endpoint=endpoint, timeout=2)
        try:
            status = client.send_message('status')
            stats = client.send_message('stats')
            # Assuming here there's only a process
            pid = stats['infos'][process].keys()[0]
            uptime = int(stats['infos'][process][pid]['age'])
            default['pid'] = pid
            default['status'] = status['statuses'][process]
            default['uptime'] = humanize.naturaltime(datetime.datetime.now() - datetime.timedelta(seconds=uptime))
        except Exception as exc:
            if'TIMED OUT' in exc.message.upper():
                default['status'] = 'stopped'
    return default
