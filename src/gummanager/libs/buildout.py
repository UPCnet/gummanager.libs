from gummanager.libs.utils import padded_log, configure_ini

import tarfile
from StringIO import StringIO


class RemoteBuildoutHelper(object):
    folder = ''
    cfgfile = ''
    _remote_config_files = {}

    def __init__(self, remoteConnection, python_interpreter, config):
        self.remote = remoteConnection
        self.python_interpreter = python_interpreter
        self.config = config

    def clone(self, repo):
        code, stdout = self.remote.execute('git clone {} {}  --progress > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            repo,
            self.folder)
        )
        padded_log(stdout)

        file_exists = self.remote.file_exists('{}/bootstrap.py'.format(self.folder))
        return code == 0 and file_exists

    def bootstrap(self, cfgfile):
        code, stdout = self.remote.execute('cd {} && {} bootstrap.py -c {}'.format(
            self.folder,
            self.python_interpreter,
            cfgfile)
        )
        self.cfgfile = cfgfile
        padded_log(stdout)

        file_exists = self.remote.file_exists('{}/bootstrap.py'.format(self.folder))
        return code == 0 and file_exists

    def configure_file(self, cfgfile, params):
        customizeme = configure_ini(
            string=self.remote.get_file("{}/{}".format(self.folder, cfgfile)),
            params=params)

        success = self.remote.put_file("{}/{}".format(self.folder, cfgfile), customizeme)
        return success

    def execute(self):
        def buildout_log(string):
            padded_log(
                string,
                filters=['Installing', 'Generated', 'Got'])

        code, stdout = self.remote.execute(
            'cd {} && ./bin/buildout -c {}'.format(self.folder, self.cfgfile),
            _out=buildout_log
        )
        circus_installed = self.remote.file_exists('{}/config/circus.ini'.format(self.folder))
        return code == 0 and circus_installed

    def change_permissions(self, uid):
        code, stdout = self.remote.execute('cd {0} && chown {1}:{1}'.format(self.folder, uid))
        return code == 0

    @property
    def config_files(self):
        if not self._remote_config_files:
            code, stdout = self.remote.execute('cd {} && find . -wholename "./*/config/*.ini" | tar cv -O -T -'.format(self.config.instances_root))
            if stdout:
                tar = tarfile.open(mode="r:", fileobj=StringIO(stdout))
                for taredfile in tar.members:
                    instance_name, config, filename = taredfile.name.strip('./').split('/')
                    self._remote_config_files.setdefault(instance_name, {})
                    extracted_file = tar.extractfile(taredfile.name)
                    self._remote_config_files[instance_name][filename] = extracted_file.read()
        return self._remote_config_files
