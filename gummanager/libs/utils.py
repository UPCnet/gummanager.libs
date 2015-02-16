from sh import ssh, ErrorReturnCode
import requests
from StringIO import StringIO
from configobj import ConfigObj
from circus.client import CircusClient
import datetime
import humanize
import re
from blessings import Terminal

# import to connect through xmlrpc with supervisor
import xmlrpclib

term = Terminal()
DEBUG_MODE = True


def process_output(lines, prefix=''):
    messages = []
    for line in lines.split('\n'):
        effective_prefix = prefix if line.strip() else ''
        messages.append(message_log(effective_prefix + line))
    return messages


def success(result, message):
    messages = process_output(result)
    messages.append(success_log(message))
    return messages


def error(result, message):
    messages = process_output(result, prefix='> ')
    messages.append(error_log(message))
    return messages


class StepError(Exception):
    def __init__(self, message, *args, **kwargs):
        super(StepError, self).__init__(message, *args, **kwargs)
        if isinstance(message, str):
            self.message = error_log(message)


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
            message = ''
            if DEBUG_MODE:
                message += error_code.stderr
            if do_raise:
                raise StepError(error(message, 'Error on remote command "{}"'.format(command)))
            return 1, error_code.stderr

        return result.exit_code, result.stdout

    def mkdir(self, folder, **kwargs):
        code, stdout = self.execute('mkdir {}'.format(folder), **kwargs)
        return code == 0

    def file_exists(self, filename, **kwargs):
        code, stdout = self.execute('ls {}'.format(filename), **kwargs)
        return code == 0

    def get_file(self, filename, **kwargs):
        code, stdout = self.execute('cat {}'.format(filename), **kwargs)
        return stdout

    def put_file(self, filename, content, **kwargs):
        code, stdout = self.execute("cat > {}".format(filename), _in=content, **kwargs)
        return self.get_file(filename) == content


def error_log(message):
    if isinstance(message, str):
        return (0, message)
    else:
        return message


def raising_error_log(message):
    if isinstance(message, str):
        return (4, message)
    else:
        return message


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

    multilines = re.findall(r'([^=] +[^\n=]+)(?=\n)', text, re.MULTILINE)
    for multiline in multilines:
        text = text.replace(multiline, ' ' + multiline.lstrip())

    input_config = StringIO(text)
    return ConfigObj(input_config, encoding="utf-8", list_values=False)


def configure_ini(string=None, filename=None, url=None, params={}, append=False):

    config = parse_ini_from(string=string, filename=filename, url=url, params=params)
    for section_name, section_items in params.items():
        section = config[section_name]

        for element_name, value in section_items.items():
            if isinstance(value, list):
                separator = '\n' + ' ' * (len(element_name) + 3)
                if append and element_name in section:
                    existing = [a.strip() for a in section[element_name].split(' ')]
                    value = existing + value
                value = separator.join(list(set(value)))
            section[element_name] = value

    out = StringIO()
    config.default_encoding = 'utf-8'
    config.write(out)
    out.seek(0)

    text = out.read()
    text = text.replace('""', '')
    text = text.replace("'''", '')
    return text


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

def supervisor_status(supervisor_xmlrpc=None,instance_name=None):
    default = {
        'pid': 'unknown',
        'status': 'unknown',
        'uptime': 'unknown'
    }

    if supervisor_xmlrpc and instance_name:
        try:
            supervisor_server = xmlrpclib.Server(supervisor_xmlrpc)
            try:
                osiris_name = 'osiris_' + instance_name
                process_info = supervisor_server.supervisor.getProcessInfo(osiris_name)
                default['status'] = process_info['statename']
                default['pid'] = process_info['pid']
                default['uptime'] = process_info['description']

            except:
                default['status'] = "supervisor contacted but instance status not retrieved"
        except Exception as exc:
            default['status']="Can't contact to supervisor"

        
    return default


def admin_password_for_branch(branch_name):
    return '{}secret'.format(branch_name)
