from gummanager.libs.utils import padded_log, configure_ini, StepError, error
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

    def add(self, files):
        code, stdout = self.remote.execute('cd {} && git add {} > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            ' '.join(files)),
            do_raise=True
        )

        success = code == 0
        return success

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

    def merge_commit(self, branch_name):
        commit_message = 'Merged from {}'.format(branch_name)
        code, stdout = self.remote.execute('cd {} && git commit -m "{}"> /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
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
    def conflicted_files(self):
        code, stdout = self.remote.execute('cd {} && git status > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder)
        )
        if code != 0:
            stdout = self.remote.get_file('/tmp/gitlog')
        conflicts = []
        # First: search for a conflict status
        match = re.search(r"Unmerged paths", stdout, re.IGNORECASE)
        if match:
            unmerged_paths = stdout[match.end():]
            conflicts = re.findall(r'\#\s+(?:.*?):\s+(.*?)\n', unmerged_paths)

        return conflicts

    @property
    def status(self):
        code, stdout = self.remote.execute('cd {} && git status > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder)
        )
        if code != 0:
            stdout = self.remote.get_file('/tmp/gitlog')

        # First: search for a conflict status
        match = re.search(r"Unmerged paths", stdout, re.IGNORECASE)
        if match:
            return 'conflict'

        # Second: search for a uncommitted status
        match = re.search(r"you are still merging", stdout, re.IGNORECASE)
        if match:
            return 'uncommitted'

        # Third: search for a normal pending to be committed
        match = re.search(r"changes to be committed", stdout, re.IGNORECASE)
        if match:
            return 'uncommitted'

        match = re.search(r"nothing .*? commit(.*?)\n", stdout)
        return 'clean' if match else 'dirty'

    # Methods to use external

    def clone(self, repo, branch):
        code, stdout = self.remote.execute('git clone -b {} {} {}  --progress > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            branch,
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

    def execute(self, update=False):
        modifiers = '-N' if update else ''

        commands = [
            'cd {}'.format(self.folder),
            'touch var/log/buildout.log',
            './bin/buildout {} -c {} > var/log/buildout.log'.format(modifiers, self.cfgfile)
        ]
        self.logecho.start()
        code, stdout = self.remote.execute(' && '.join(commands))
        self.logecho.stop()
        supervisor_installed = self.remote.file_exists('{}/parts/supervisor/supervisord.conf'.format(self.folder))
        if not(code == 0 and supervisor_installed):
            raise StepError(error(stdout, 'Error on buildout execution'))
        return True

    def change_permissions(self, uid):
        code, stdout = self.remote.execute('cd {0} && chown -R {1}:{1} .'.format(self.folder, uid), do_raise=True)
        return code == 0

    def commit_to_local_branch(self, git_branch_name, files=[]):
        code, stdout = self.remote.execute('cd {} && git checkout -b {} > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            git_branch_name),
            do_raise=True
        )
        success = self.add(files)
        if not success:
            raise StepError('Error adding Files')

        success = self.current_branch == git_branch_name
        if success:
            commit_log = self.commit()

        success = self.status == "clean"
        if not(code == 0 and success):
            raise StepError('Error when commiting to local branch')
        return commit_log + padded_log(stdout, filters=['Switched', 'M\t'], print_stdout=False)

    def switch_branch(self, branch_name):
        code, stdout = self.remote.execute('cd {} && git checkout {} > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            branch_name),
            do_raise=True
        )
        return self.current_branch

    def pull(self):
        code, stdout = self.remote.execute('cd {} && git pull > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder),
            do_raise=False
        )
        return stdout

    def merge(self, branch_name):
        code, stdout = self.remote.execute('cd {} && git merge {} --no-commit > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            branch_name),
            do_raise=False
        )
        return stdout

    def restore_theirs(self, filename):
        code, stdout = self.remote.execute('cd {} && git checkout --theirs {} > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            filename),
            do_raise=True
        )
        code, stdout = self.remote.execute('cd {} && git add {} > /tmp/gitlog 2>&1 && cat /tmp/gitlog'.format(
            self.folder,
            filename),
            do_raise=True
        )
        return stdout

    def upgrade(self, fetch_from, git_branch_name):
        # Check if the repository is clean and in the local branch
        is_clean = self.status == 'clean'
        is_local = self.current_branch == git_branch_name

        messages = ''

        # If repo is clean, try to switch to local branch
        if not is_local and is_clean:
            current = self.switch_branch(git_branch_name)
            messages += "Switched to branch {}".format(current)
            is_local = self.current_branch == git_branch_name

        if not is_local:
            raise StepError('Check that git repo is on {} on branch {}'.format(
                self.folder,
                git_branch_name
            ))

        if not is_clean:
            raise StepError('Check that git repo on {} is clean'.format(
                self.folder,
                git_branch_name
            ))

        # Go back to master
        current = self.switch_branch(fetch_from)
        if not(self.status == "clean" and fetch_from == current):
            raise StepError('Error after switching to {} branch'.format(fetch_from))

        # Pull changes from upstream
        messages += self.pull()
        if self.status != "clean":
            raise StepError('Error after pulling changes from {}'.format(fetch_from))

        # Go back to local branch
        current = self.switch_branch(git_branch_name)
        if not(self.status == "clean" and git_branch_name == current):
            raise StepError('Error after switching to {} branch'.format(fetch_from))

        # Merge upstream with local
        messages += self.merge(fetch_from)
        if self.status == 'conflict':
            # Autosolve versions.cfg conflicts. Remote wins
            if self.conflicted_files == ['versions.cfg']:
                self.restore_theirs('versions.cfg')
                messages += "Conflict in versions.cfg, picking master version.\n"
            else:
                raise StepError('Conflict(s) detected, please solve them manually'.format(fetch_from))

        if self.status == 'uncommitted':
            messages += self.merge_commit(fetch_from).split('>')[0]

        if not(self.status == "clean"):
            raise StepError('Error after commiting merge, status {} ?'.format(self.status))

        return messages

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
