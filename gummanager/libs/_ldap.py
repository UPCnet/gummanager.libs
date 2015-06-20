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
from ldapurl import LDAPUrl
import os
import re

PORTS_SCHEME_MAPPING = {
    636: 'ldaps://',
    389: 'ldap://'
}


def catch_ldap_errors(func):
    def inner(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except ldap.LDAPError as error:
            reason = error.message['desc']
            ld = args[0]
            if reason == 'No such object':
                if func.__name__ == 'get_users':
                    raise StepError('There\'s no branch "{}" @ {}'.format(ld.dn, ld.ldap_uri))

            elif reason == 'Invalid credentials':
                if func.__name__ == 'authenticate':
                    username = kwargs.get('username', '')
                    raise StepError("Wrong password for user {}".format(username))

            elif reason == 'Can\'t contact LDAP server':
                raise StepError('Ldap server "{}" is not responding'.format(ld.ldap_uri))

            elif reason == 'Already exists':
                if func.__name__ == 'add_ou_by_dn':
                    dn = args[1]
                    raise StepError('There\'s an existing ou "{}" @ {}'.format(dn, ld.ldap_uri))

            raise StepError('LDAP error "{}" on method "{}". Check params and try again'.format(reason, func.__name__))
    return inner


class LdapServer(object):
    def __init__(self, config, *args, **kwargs):

        self.config = config
        self.set_server()
        self.branch = None
        self.user_scope = getattr(ldap, self.config.user_scope, 'SCOPE_SUBTREE')
        self.group_scope = getattr(ldap, self.config.group_scope, 'SCOPE_SUBTREE')

    def ssha(self, password):

        salt = os.urandom(16)
        return '{ssha}' + base64.b64encode(hashlib.sha1(password + salt).digest() + salt)

    def dn_from_username(self, username):
        return 'cn={},{}'.format(username, self.effective_users_dn)

    def dn_from_groupname(self, groupname):
        return 'cn={},{}'.format(groupname, self.effective_groups_dn)

    @property
    def effective_admin_dn(self):
        if self.config.branches.enabled:
            return 'cn={admin_cn},ou={branch},{base_dn}'.format(branch=self.branch, **self.config.branches)
        else:
            return self.config.admin_dn

    @property
    def effective_admin_password(self):
        if self.config.branches.enabled:
            return self.config.branches.admin_password
        else:
            return self.config.admin_password

    @property
    def effective_users_dn(self):
        return self.config.users_base_dn.format(branch=self.branch)

    @property
    def effective_groups_dn(self):
        return self.config.group_base_dn.format(branch=self.branch)

    # checked
    def set_branch(self, branch):
        """
            Sets the active branch. If not called, branch is None by default
        """
        self.branch = branch

    def set_server(self):
        """
            Sanity parse & check of ldap uri and sets a valid expected url
        """
        clean_url = self.config.server.strip()

        # Set a safe default for ldap protocol if missing
        if not re.match(r'ldaps?://', clean_url):
            # Search for specified port and fallback to standard if missing
            matchport = re.search(r':(\d+)', clean_url)
            if not matchport:
                port = 389
            else:
                port = int(matchport.groups(0))

            # Set the schema based on standar ports, fallback to standard if
            # port doesn't match any of standar ports
            scheme = PORTS_SCHEME_MAPPING.get(port, 'ldap://')
            ldap_uri = scheme + clean_url
        else:
            ldap_uri = clean_url

        ldapurl = LDAPUrl(ldap_uri)
        self.ldap_uri = '{urlscheme}://{hostport}'.format(**ldapurl.__dict__)

    def exists(self, username):
        users = self.get_users()
        return len([a for a in users if a['name'] == username]) > 0

    @catch_ldap_errors
    def connect(self, auth=True, **kwargs):
        """
            Connect to ldap and optionallly bind

            After initialization, if auth=True, a bind will be performed using the
            base admin credentials. If you want to authenticate with other credentials
            set auth=False and do the authentication later.
        """
        self.ld = ldap.initialize(self.ldap_uri)
        if auth:
            return self.authenticate(
                username=self.effective_admin_dn,
                password=self.effective_admin_password,
                **kwargs)

        return True

    @catch_ldap_errors
    def disconnect(self):
        """
            Unbinds and disconnects the ldap server connection
        """
        self.ld.unbind_s()

    @catch_ldap_errors
    def authenticate(self, username, password):
        """
        """
        self.ld.simple_bind_s(username, password)

        # if not self.exists(username):
        #     raise StepError("User {} doesn't exists in branch {}".format(username, branch))

        #     if userdn:
        #         if not self.exists(username, branch):
        #             raise StepError("User {} doesn't exists in branch {}".format(username, branch))
        #         self.disconnect()
        #         self.connect(auth=False)
        # else:
        #     if userdn:
        #         self.cd(self.config.branch_users_dn)

        # user_dn = "cn={},{}".format(username, self.dn)
        # self.ld.simple_bind_s(user_dn, password)

    @catch_ldap_errors
    def add_ou_by_dn(self, dn):
        ou = re.search(r'ou=(.*?)', dn).groups()[0]

        ldif = modlist.addModlist({
            'objectclass': ['top', 'organizationalUnit'],
            'ou': ou,
            'description': ou
        })
        self.ld.add_s(dn, ldif)

    @catch_ldap_errors
    def add_ldap_user_by_dn(self, dn, fullname, password):
        """
            Adds a new ldap user.

            Extracts the username from the first cn= element on dn
        """
        cn = re.search(r'cn=(.*?)', dn).groups()[0]
        ldif = modlist.addModlist({
            'objectclass': ['top', 'organizationalPerson', 'person', 'inetOrgPerson'],
            'cn': cn.encode('utf-8'),
            'sn': fullname.encode('utf-8'),
            'userPassword': self.ssha(password.encode('utf-8'))
        })
        self.ld.add_s(dn, ldif)

    # checked
    @catch_ldap_errors
    def add_group_by_dn(self, dn, user_dns=[]):
        """
        """
        cn = re.search(r'cn=(.*?),(.*?)', dn).groups()[0]

        ldif = modlist.addModlist({
            'objectclass': ['top', 'groupOfNames'],
            'cn': cn,
            'member': user_dns
        })
        self.ld.add_s(dn, ldif)

    def add_ldap_user(self, username, fullname, password):
        """
            Inserts a new user into the current users dn
        """
        dn = self.dn_from_username(username)
        self.add_ldap_user_by_dn(dn, fullname, password)

    @catch_ldap_errors
    def del_user(self, username):
        """
            Deletes a user frmo the current users dn
        """
        user_dn = self.dn_from_username(username)
        self.ld.delete_s(user_dn)

    @catch_ldap_errors
    def get_users(self, filter=None):
        ldap_result_id = self.ld.search(
            self.effective_users_dn,
            self.user_scope,
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
                    # SN fallback to CN if not present
                    cn = result_data[0][1]['cn'][0]
                    sn = result_data[0][1].get('sn', [cn])[0]
                    entry = {'name': cn, 'sn': sn}
                    if not filter or filter.lower() in entry['name'].lower() + entry['sn'].lower():
                        result_set.append(entry)
        return result_set

    @catch_ldap_errors
    def get_group_users(self, group_name, filter=None):
        ldap_result_id = self.ld.search(
            self.effective_groups_base_dn,
            self.user_scope,
            "cn={}".format(group_name),
            None
        )
        result_set = []
        while 1:
            result_type, result_data = self.ld.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set += [re.match("cn=(.*?),.*", member).groups()[0] for member in result_data[0][1].get('member')]
        return result_set

    @catch_ldap_errors
    def get_groups(self):
        try:
            ldap_result_id = self.ld.search(
                self.effective_groups_base_dn,
                self.group_scope,
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

    def get_branch(self, branch):
        self.set_branch(branch)
        groups = self.get_groups()
        users = self.get_users()
        instance = OrderedDict()
        instance['name'] = branch
        instance['groups'] = groups
        instance['users'] = users
        return instance

    @catch_ldap_errors
    def get_branches(self):
        ldap_result_id = self.ld.search(
            self.config.branches.base_dn,
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

        # Look for users without password
        users_without_password = [a['username'] for a in users if a['password'].strip() == '']
        if users_without_password:
            raise Exception('Found users without password: {}'.format(', '.join(users_without_password)))

    # Commands

    @command
    def add_branch(self, branch):
        if not self.config.branches.enabled:
            yield error_log('Branches are not enabled on this LDAP')
        if self.config.readonly:
            yield error_log('This LDAP is configured as read-only')

        self.connect()
        self.add_ou_by_dn("ou={branch},{branches.base_dn}".format(**self.config))

        self.set_branch(branch)

        branch_restricted_user_dn = "cn={branches.restricted_cn},ou={branch},{branches.base_dn}".format(**self.config)
        branch_admin_user_dn = "cn={branches.admin_cn},ou={branch},{branches.base_dn}".format(**self.config)

        self.set_branch(branch)
        self.add_ldap_user_by_dn(branch_admin_user_dn, 'LDAP Access User', self.config.branches.admin_password)
        self.add_ldap_user_by_dn(branch_restricted_user_dn, 'Restricted User', admin_password_for_branch(branch))

        self.add_group_by_dn('cn=Managers,ou={branch},{branches.base_dn}'.format(**self.config), user_dns=[branch_admin_user_dn])
        self.add_ou_by_dn('ou=groups,ou={branch},{branches.base_dn}'.format(**self.config))
        self.add_ou_by_dn('ou=users,ou={branch},{branches.base_dn}'.format(**self.config))

        # Add plain users
        for user in self.config.branches.base_users:
            self.add_ldap_user(user.username, user.username, user.password)

        self.disconnect()
        yield success_log("Branch {} successfully created".format(branch))

    @command
    def list_branches(self):
        if not self.config.branches.enabled:
            yield error_log('Branches are not enabled on this LDAP')
        self.connect()
        branches = self.get_branches()
        self.disconnect()
        yield return_value(branches)

    @command
    def add_user(self, branch, username, password):
        if self.config.readonly:
            yield error_log('This LDAP is configured as read-only')
        self.set_branch(branch)
        self.connect(auth=False)
        self.authenticate(
            username=self.effective_admin_dn,
            password=self.effective_admin_password,
        )
        self.add_ldap_user(username, username, password)
        self.disconnect()

        yield success_log("User {} successfully added".format(username))

    @command
    def add_users(self, branch, usersfile):
        if self.config.readonly:
            yield error_log('This LDAP is configured as read-only')

        self.set_branch(branch)
        self.connect(auth=False)
        self.authenticate(
            username=self.effective_admin_dn,
            password=self.effective_admin_password)

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
    def list_users(self, branch, filter):
        self.set_branch(branch)
        self.connect()
        users = self.get_users(filter=filter)
        self.disconnect()
        yield return_value(users)

    @command
    def delete_user(self, branch, username):
        if self.config.readonly:
            yield error_log('This LDAP is configured as read-only')
        self.set_branch(branch)
        self.connect()
        self.del_user(username)
        self.disconnect()
        yield success_log("User {} deleted from branch".format(username))

    @command
    def check_user(self, branch, username, password):
        self.set_branch(branch)
        self.connect()
        self.authenticate(self.dn_from_username(username), password)
        self.disconnect()
        yield success_log("User {} exists and matches provided password".format(username))
