from gummanager.libs.utils import padded_log, configure_ini


class RemoteBuildoutHelper(object):
    folder = ''
    cfgfile = ''

    def __init__(self, remoteConnection, python_interpreter):
        self.remote = remoteConnection
        self.python_interpreter = python_interpreter

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
            string=self.remote.get_file(cfgfile),
            params=params)

        success = self.remote.put_file("{}/customizeme.cfg".format(self.folder), customizeme)
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
