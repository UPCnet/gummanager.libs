# -*- coding: utf-8 -*-
from collections import Counter
from collections import OrderedDict
from gummanager.libs.batch import read_users_file
from gummanager.libs.utils import StepError
from gummanager.libs.utils import admin_password_for_branch
from gummanager.libs.utils import command
from gummanager.libs.utils import error_log
from gummanager.libs.utils import raising_error_log
from gummanager.libs.utils import return_value
from gummanager.libs.utils import step_log
from gummanager.libs.utils import success_log

import base64
import hashlib
import ldap
import ldap.modlist as modlist
import os


def catch_ldap_errors(func):
    def inner(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except ldap.LDAPError as error:
            reason = error.message['desc']
            ld = args[0]
            if reason == 'No such object':
                if func.__name__ == 'get_branch_users':
                    branch_name = args[1]
                    raise StepError('There\'s no branch named "{}" at {}'.format(branch_name, ld.dn))

            elif reason == 'Invalid credentials':
                if func.__name__ == 'authenticate':
                    username = ld.config.admin_cn if len(args) == 1 else args[1]
                    raise StepError("Wrong password for user {} @ {}".format(username, ld.ldap_uri))

            elif reason == 'Can\'t contact LDAP server':
                raise StepError('Ldap server "{}" is not responding'.format(ld.ldap_uri))

            elif reason == 'Already exists':
                if func.__name__ == 'add_ou':
                    branch_name = args[1]
                    raise StepError('There\'s an existing branch named "{}" @ {}'.format(branch_name, ld.ldap_uri))

            raise StepError('LDAP error "{}" on method "{}". Check params and try again'.format(reason, func.__name__))
    return inner


class LdapServer(object):
    def __init__(self, config, *args, **kwargs):

        self.config = config

        self.set_server(**self.config)
        self.leaf_dn = ''

    @property
    def dn(self):
        base_dn = self.config.base_dn
        if self.leaf_dn:
            base_dn = '{},{}'.format(self.leaf_dn, self.config.base_dn)
        return base_dn

    def ssha(self, password):

        salt = os.urandom(16)
        return '{ssha}' + base64.b64encode(hashlib.sha1(password + salt).digest() + salt)

    def set_server(self, **params):
        self.ldap_uri = 'ldaps://{server}:{port}'.format(**params)

    def exists(self, username, branch):
        users = self.get_branch_users(branch)
        return len([a for a in users if a['name'] == username]) > 0

    def cd_branch(self, branch_name, users=True):
        self.cd('/')
        if users:
            self.cd('ou=users,ou={}'.format(branch_name))
        else:
            self.cd('ou={}'.format(branch_name))

    def cd(self, dn):
        if dn == '/':
            self.leaf_dn = ''
        else:
            self.leaf_dn = dn

    @catch_ldap_errors
    def connect(self, auth=True):
        self.ld = ldap.initialize(self.ldap_uri)
        if auth:
            return self.authenticate(self.config.admin_cn, self.config.admin_password)

        return True

    @catch_ldap_errors
    def disconnect(self):
        self.ld.unbind_s()

    @catch_ldap_errors
    def authenticate(self, username, password, branch=None, userdn=False):
        self.cd('/')
        if branch:
            self.cd_branch(branch, userdn)
            if userdn:
                if not self.exists(username, branch):
                    raise StepError("User {} doesn't exists in branch {}".format(username, branch))
                self.disconnect()
                self.connect(auth=False)
        user_dn = "cn={},{}".format(username, self.dn)
        self.ld.simple_bind_s(user_dn, password)

    @catch_ldap_errors
    def add_ou(self, ou_name):
        dn = 'ou={},{}'.format(ou_name, self.dn)

        ldif = modlist.addModlist({
            'objectclass': ['top', 'organizationalUnit'],
            'ou': ou_name,
            'description': ou_name
        })
        self.ld.add_s(dn, ldif)

    @catch_ldap_errors
    def add_ldap_user(self, username, fullname, password, **kwargs):
        dn = 'cn={},{}'.format(username, self.dn)

        ldif = modlist.addModlist({
            'objectclass': ['top', 'organizationalPerson', 'person', 'inetOrgPerson'],
            'cn': username.encode('utf-8'),
            'sn': fullname.encode('utf-8'),
            'userPassword': self.ssha(password.encode('utf-8'))
        })
        self.ld.add_s(dn, ldif)

    @catch_ldap_errors
    def del_user(self, user_name):
        dn = 'cn={},{}'.format(user_name, self.dn)
        self.ld.delete_s(dn)

    @catch_ldap_errors
    def add_group(self, group_name, users=[]):
        dn = 'cn={},{}'.format(group_name, self.dn)

        members = []
        members.append('cn={},{}'.format('ldap', self.dn))

        ldif = modlist.addModlist({
            'objectclass': ['top', 'groupOfNames'],
            'cn': group_name,
            'member': members
        })
        self.ld.add_s(dn, ldif)

    @catch_ldap_errors
    def get_branch_users(self, branch_name, filter=None):
        self.cd('/')
        self.cd('ou=users,ou={}'.format(branch_name))

        ldap_result_id = self.ld.search(
            self.dn,
            ldap.SCOPE_SUBTREE,
            "cn=*",
            None
        )
        result_set = []
        while 1:
            result_type, result_data = self.ld.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    entry = {
                        'name': result_data[0][1]['cn'][0],
                        'sn': result_data[0][1]['sn'][0]
                    }
                    if not filter or filter.lower() in entry['name'].lower() + entry['sn'].lower():
                        result_set.append(entry)
        return result_set

    @catch_ldap_errors
    def get_branch_groups(self, branch_name):
        self.cd('/')
        self.cd('ou=groups,ou={}'.format(branch_name))
        try:
            ldap_result_id = self.ld.search(
                self.dn,
                ldap.SCOPE_SUBTREE,
                "cn=*",
                None
            )
            result_set = []
            while 1:
                result_type, result_data = self.ld.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append({
                            'name': result_data[0][1]['cn'][0],
                            'members': result_data[0][1].get('member', result_data[0][1].get('uniqueMember'))
                        })
            return result_set
        except ldap.LDAPError, e:
            print e

    def get_branch(self, branch_name):
        groups = self.get_branch_groups(branch_name)
        users = self.get_branch_users(branch_name)
        instance = OrderedDict()
        instance['name'] = branch_name
        instance['groups'] = groups
        instance['users'] = users
        return instance

    @catch_ldap_errors
    def get_branches(self):
        ldap_result_id = self.ld.search(
            self.config.base_dn,
            ldap.SCOPE_ONELEVEL,
            "ou=*",
            None
        )
        result_set = []
        while 1:
            result_type, result_data = self.ld.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                branch_name = result_data[0][1]['ou'][0]
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(self.get_branch(branch_name))
        return result_set

    @staticmethod
    def check_users(users):
        """
            Check user list consistency, raises on validation errors
        """

        # Look for repeated users
        usernames = [a['username'] for a in users]
        duplicates = [k for k, v in Counter(usernames).items() if v > 1]
        if duplicates:
            raise Exception('Found duplicated users: {}'.format(', '.join(duplicates)))

        # Look for users withuot password
        users_without_password = [a['username'] for a in users if a['password'].strip() == '']
        if users_without_password:
            raise Exception('Found users without password: {}'.format(', '.join(users_without_password)))

    # Commands

    @command
    def add_branch(self, branch_name):
        self.connect()

        self.cd('/')
        self.add_ou(branch_name)
        self.cd('ou={}'.format(branch_name))
        self.add_ldap_user(self.config.branch_admin_cn, 'LDAP Access User', self.config.branch_admin_password)
        self.add_ldap_user('restricted', 'Restricted User', admin_password_for_branch(branch_name))

        self.add_group('Managers')
        self.add_ou('groups')
        self.add_ou('users')

        # Add plain users
        self.cd('ou=users,ou={}'.format(branch_name))
        for user in self.config.base_users:
            self.add_ldap_user(user.username, user.username, user.password)

        self.disconnect()
        yield success_log("Branch {} successfully created".format(branch_name))

    @command
    def list_branches(self):
        self.connect()
        branches = self.get_branches()
        self.disconnect()
        yield return_value(branches)

    @command
    def add_user(self, branch_name, username, password):
        self.connect(auth=False)
        self.authenticate(
            username=self.config.branch_admin_cn,
            password=self.config.branch_admin_password,
            branch=branch_name,
            userdn=False)

        self.cd('/')
        self.cd('ou=users,ou={}'.format(branch_name))
        self.add_ldap_user(username, username, password)

        self.disconnect()

        yield success_log("User {} successfully added".format(username))

    @command
    def add_users(self, branch_name, usersfile):
        self.connect(auth=False)
        self.authenticate(
            username=self.config['branch_admin_cn'],
            password=self.config['branch_admin_password'],
            branch=branch_name,
            userdn=False)

        self.cd('/')
        self.cd('ou=users,ou={}'.format(branch_name))

        try:
            users = read_users_file(usersfile, required_fields=['username', 'fullname', 'password'])
        except Exception as exc:
            error_message = 'Error parsing users file {}: {{}}'.format(usersfile)
            yield raising_error_log(error_message.format(exc.message))

        try:
            self.check_users(users)
        except Exception as exc:
            yield raising_error_log(exc.message)

        yield step_log('Creating {} users '.format(len(users)))
        for count, user in enumerate(users, start=1):
            if not user:
                yield error_log('Error parsing user at line #{}'.format(count))
                continue
            try:
                self.add_ldap_user(**user)
                yield success_log('User {} created'.format(user['username']))
            except ldap.ALREADY_EXISTS:
                yield error_log('User {} already exists'.format(user['username']))
            except Exception as exc:
                yield error_log('Error creating user {}: {}'.format(user['username']), exc.__repr__())

        self.disconnect()

    @command
    def list_users(self, branch_name, filter):
        self.connect()
        users = self.get_branch_users(branch_name, filter=filter)
        self.disconnect()
        yield return_value(users)

    @command
    def delete_user(self, branch_name, username):
        self.connect()
        self.cd('/')
        self.cd('ou=users,ou={}'.format(branch_name))
        self.del_user(username)
        self.disconnect()
        yield success_log("User {} deleted from branch".format(username))

    @command
    def check_user(self, branch, username, password):
        self.connect()
        self.authenticate(username, password, branch=branch, userdn=True)
        self.disconnect()
        yield success_log("User {} exists and matches provided password".format(username))
