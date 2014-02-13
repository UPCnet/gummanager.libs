from sh import ssh
import requests
from StringIO import StringIO
from configobj import ConfigObj

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

