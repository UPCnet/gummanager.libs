from gummanager.libs.utils import padded_log, configure_ini

import tarfile
from StringIO import StringIO
import re


class RemoteBuildoutHelper(object):
    folder = ''
    cfgfile = ''

    def __init__(self, remoteConnection, python_interpreter, config):
        self.remote = remoteConnection
        self.python_interpreter = python_interpreter
        self.config = config
        self._remote_config_files = {}

    def commit_to_local_branch(self, git_branch_name):
        code, stdout = self.remote.execute('cd {} && git checkout -b {} > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            git_branch_name)
        )
        if code != 0:
            stdout = self.remote.get_file('/tmp/gitlog')
        padded_log(stdout, filters=['Switched', 'M\t'])
        print
        success = self.current_branch == git_branch_name
        if success:
            success = self.commit()

        success = self.status == "clean"
        return code == 0 and success

    def commit(self):
        commit_message = 'Setup custom configuration'
        code, stdout = self.remote.execute('cd {} && git commit . -m "{}"> /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            commit_message)
        )
        if code != 0:
            stdout = self.remote.get_file('/tmp/gitlog')

        padded_log(stdout, filters=[])
        success = commit_message in stdout
        return code == 0 and success

    @property
    def current_branch(self):
        code, stdout = self.remote.execute('cd {} && git status > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder)
        )
        if code != 0:
            stdout = self.remote.get_file('/tmp/gitlog')
            padded_log(stdout, filters=['On branch'])

        match = re.search(r"branch (.*?)\n", stdout)
        branch_name = match.groups()[0] if match else None

        return branch_name if (code == 0 and branch_name) else None

    @property
    def status(self):
        code, stdout = self.remote.execute('cd {} && git status > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder)
        )
        if code != 0:
            stdout = self.remote.get_file('/tmp/gitlog')

        match = re.search(r"nothing .*? commit(.*?)\n", stdout)

        return 'clean' if match else 'dirty'

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
        code, stdout = self.remote.execute('cd {0} && chown -R {1}:{1} .'.format(self.folder, uid))
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
