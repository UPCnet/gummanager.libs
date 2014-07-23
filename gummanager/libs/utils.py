from sh import ssh, ErrorReturnCode
import requests
from StringIO import StringIO
from configobj import ConfigObj
from circus.client import CircusClient
import datetime
import humanize
import re
from blessings import Terminal

term = Terminal()
DEBUG_MODE = False


def process_output(lines):
    messages = []
    for line in lines.split('\n'):
        messages.append(message_log(line))
    return messages


def success(result, message):
    messages = process_output(result)
    messages.append(success_log(message))
    return messages


class StepError(Exception):
    pass


class ReadyCounter(object):
    def __init__(self, event):
        self.count = 0
        self.event = event

    def add(self):
        self.count += 1

    def ready(self):
        self.count -= 1
        if self.count == 0:
            self.event.set()


class RemoteConnection(object):
    def __init__(self, user, server):
        self.ssh = ssh.bake('{}@{}'.format(user, server))

    def execute(self, command, **kwargs):
        do_raise = kwargs.get('do_raise', False)
        if 'do_raise' in kwargs:
            del kwargs['do_raise']
        try:
            result = self.ssh(command, **kwargs)
        except ErrorReturnCode as error_code:
            error_message = 'Error on remote command {}'.format(command)
            if DEBUG_MODE:
                error_message += '\n' + error_code.stderr
            if do_raise:
                raise StepError(error_message)
            return 1, error_code.stderr

        return result.exit_code, result.stdout

    def file_exists(self, filename):
        code, stdout = self.execute('ls {}'.format(filename))
        return code == 0

    def get_file(self, filename):
        code, stdout = self.execute('cat {}'.format(filename))
        return stdout

    def put_file(self, filename, content):
        code, stdout = self.execute("cat > {}".format(filename), _in=content)
        return self.get_file(filename) == content


def error_log(message):
    return (0, message)


def success_log(message):
    return (1, message)


def message_log(message):
    return (2, message)


def step_log(message):
    return (3, message)


def padded_success(string):
    print term.bold_green + '    {}'.format(string) + term.normal


def padded_error(string):
    print term.bold_red + '    {}\n'.format(string) + term.normal


def padded_log(string, filters=[], print_stdout=True):
    log = []
    string = string.rstrip()
    # apply padding to rewrite lines (starting with \r)
    string = re.sub(r'([\r])', r'\1    ', string)
    lines = string.split('\n')
    for line in lines:
        matched_filter = re.search(r'({})'.format('|'.join(filters)), line)
        do_print = matched_filter or filters == []
        if do_print:
            log.append(line.rstrip())

    loglines = '\n'.join(log)
    if print_stdout:
        print loglines
    return loglines


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
    config.default_encoding = 'utf-8'
    config.write(out)
    out.seek(0)
    return out.read().replace('"', '')


def circus_control(action, endpoint=None, process=None):
    if endpoint and process:
        client = CircusClient(endpoint=endpoint, timeout=2)
        client.send_message(action)


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
            try:
                uptime = int(stats['infos'][process][pid]['age'])
                default['uptime'] = humanize.naturaltime(datetime.datetime.now() - datetime.timedelta(seconds=uptime))
                default['pid'] = pid
            except:
                # circus running but process stopped
                pass
            default['status'] = status['statuses'][process]

        except Exception as exc:
            if'TIMED OUT' in exc.message.upper():
                # circus stopped
                default['status'] = 'unknown'
    return default


def admin_password_for_branch(branch_name):
    return '{}secret'.format(branch_name)
