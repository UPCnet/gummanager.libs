from sh import ssh
import requests
from StringIO import StringIO
from configobj import ConfigObj
from circus.client import CircusClient
import datetime
import humanize

class SSH(object):
    def __init__(self, user, server):
        self.ssh = ssh.bake('{}@{}'.format(user, server))

    def __call__(self, command, **kwargs):
        try:
            result = self.ssh(command, **kwargs)
        except:
            return None, ''

        return result.exit_code, result.stdout


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
        except:
            pass
    return default