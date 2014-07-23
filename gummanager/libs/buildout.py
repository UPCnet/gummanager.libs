from gummanager.libs.utils import padded_log, configure_ini, StepError

import tarfile
from StringIO import StringIO
import re


class RemoteBuildoutHelper(object):
    folder = ''
    cfgfile = ''

    def __init__(self, remoteConnection, python_interpreter, server):
        self.remote = remoteConnection
        self.python_interpreter = python_interpreter
        self.config = server.config
        self._remote_config_files = {}
        self.logecho = None

    def reload(self):
        self._remote_config_files = {}

    def commit(self):
        commit_message = 'Setup custom configuration'
        code, stdout = self.remote.execute('cd {} && git commit . -m "{}"> /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            commit_message),
            do_raise=True
        )

        success = commit_message in stdout
        if not success:
            raise StepError('Error commiting, unexpected commit message')
        return stdout

    @property
    def current_branch(self):
        code, stdout = self.remote.execute('cd {} && git status > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder)
        )
        if code != 0:
            stdout = self.remote.get_file('/tmp/gitlog')

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

    # Methods to use external

    def clone(self, repo):
        code, stdout = self.remote.execute('git clone {} {}  --progress > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            repo,
            self.folder)
        )

        file_exists = self.remote.file_exists('{}/bootstrap.py'.format(self.folder))
        if not(code == 0 and file_exists):
            raise StepError('Error on cloning {}'.format(repo))
        return stdout

    def bootstrap(self):
        code, stdout = self.remote.execute('cd {} && {} bootstrap.py -c {}'.format(
            self.folder,
            self.python_interpreter,
            self.cfgfile)
        )

        file_exists = self.remote.file_exists('{}/bootstrap.py'.format(self.folder))
        if not(code == 0 and file_exists):
            raise StepError('Error on bootstraping {}'.format(self.folder))
        return stdout

    def configure_file(self, cfgfile, params):
        remote_file = "{}/{}".format(self.folder, cfgfile)
        customizeme = configure_ini(
            string=self.remote.get_file(remote_file),
            params=params)

        success = self.remote.put_file("{}/{}".format(self.folder, cfgfile), customizeme)
        if not success:
            raise StepError('Error when configuring {}'.format(remote_file))
        return True

    def execute(self):
        commands = [
            'cd {}'.format(self.folder),
            'touch var/log/buildout.log',
            './bin/buildout -c {} > var/log/buildout.log'.format(self.cfgfile)
        ]
        self.logecho.start()
        code, stdout = self.remote.execute(' && '.join(commands))
        self.logecho.stop()
        circus_installed = self.remote.file_exists('{}/config/circus.ini'.format(self.folder))
        if not(code == 0 and circus_installed):
            raise StepError('Error on buildout execution')
        return True

    def change_permissions(self, uid):
        code, stdout = self.remote.execute('cd {0} && chown -R {1}:{1} .'.format(self.folder, uid), do_raise=True)
        return code == 0

    def commit_to_local_branch(self, git_branch_name):
        code, stdout = self.remote.execute('cd {} && git checkout -b {} > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            git_branch_name),
            do_raise=True
        )

        success = self.current_branch == git_branch_name
        if success:
            commit_log = self.commit()

        success = self.status == "clean"
        if not(code == 0 and success):
            raise StepError('Error when commiting to local branch')
        return commit_log + padded_log(stdout, filters=['Switched', 'M\t'], print_stdout=False)

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
