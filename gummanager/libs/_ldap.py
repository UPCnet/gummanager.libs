import base64
import hashlib
import ldap
import ldap.modlist as modlist
import os
from collections import OrderedDict
from gummanager.libs.utils import admin_password_for_branch


LDAP_USER_NOT_FOUND = 0x100
LDAP_INVALID_CREDENTIALS = 0x101


class LdapServer(object):
    def __init__(self, config, *args, **kwargs):

        self.config = config

        self.ldap_uri = '{server}:{port}'.format(**self.config)
        self.leaf_dn = ''

    def connect(self, auth=True):
        self.ld = ldap.initialize(self.ldap_uri)
        if auth:
            return self.authenticate(self.config.admin_cn, self.config.admin_password)

        return True

    def authenticate(self, username, password, branch=None, userdn=False):
        self.cd('/')
        if branch:
            self.cd_branch(branch, userdn)
            if userdn:
                if not self.exists(username, branch):
                    return LDAP_USER_NOT_FOUND
                self.disconnect()
                self.connect(auth=False)
        user_dn = "cn={},{}".format(username, self.dn)
        try:
            self.ld.simple_bind_s(user_dn, password)
            return True
        except:
            return LDAP_INVALID_CREDENTIALS

    def disconnect(self):
        self.ld.unbind_s()

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

    @property
    def dn(self):
        base_dn = self.config.base_dn
        if self.leaf_dn:
            base_dn = '{},{}'.format(self.leaf_dn, self.config.base_dn)
        return base_dn

    def addOU(self, ou_name):
        dn = 'ou={},{}'.format(ou_name, self.dn)

        ldif = modlist.addModlist({
            'objectclass': ['top', 'organizationalUnit'],
            'ou': ou_name,
            'description': ou_name
        })
        self.ld.add_s(dn, ldif)

    def ssha(self, password):

        salt = os.urandom(16)
        return '{ssha}' + base64.b64encode(hashlib.sha1(password + salt).digest() + salt)

    def addUser(self, user_name, display_name, password):
        dn = 'cn={},{}'.format(user_name, self.dn)

        ldif = modlist.addModlist({
            'objectclass': ['top', 'organizationalPerson', 'person', 'inetOrgPerson'],
            'cn': user_name.encode('utf-8'),
            'sn': display_name.encode('utf-8'),
            'userPassword': self.ssha(password.encode('utf-8'))
        })

        resp = self.ld.add_s(dn, ldif)

    def delUser(self, user_name):
        dn = 'cn={},{}'.format(user_name, self.dn)

        resp = self.ld.delete_s(dn)

    def addGroup(self, group_name, users=[]):
        dn = 'cn={},{}'.format(group_name, self.dn)

        members = []
        members.append('cn={},{}'.format('ldap', self.dn))

        ldif = modlist.addModlist({
            'objectclass': ['top', 'groupOfNames'],
            'cn': group_name,
            'member': members
        })
        self.ld.add_s(dn, ldif)

    def add_branch(self, branch_name):
        self.cd('/')
        self.addOU(branch_name)
        self.cd('ou={}'.format(branch_name))
        self.addUser(self.config.branch_admin_cn, 'LDAP Access User', self.config.branch_admin_password)
        self.addUser('restricted', 'Restricted User', admin_password_for_branch(branch_name))

        self.addGroup('Managers')
        self.addOU('groups')
        self.addOU('users')

        # Add plain users
        self.cd('ou=users,ou={}'.format(branch_name))
        for user in self.config.base_users:
            self.addUser(user.username, user.username, user.password)

    def get_branch_users(self, branch_name, filter=None):
        self.cd('/')
        self.cd('ou=users,ou={}'.format(branch_name))
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
                        entry = {
                            'name': result_data[0][1]['cn'][0],
                            'sn': result_data[0][1]['sn'][0]
                        }
                        if not filter or filter.lower() in entry['name'].lower() + entry['sn'].lower():
                            result_set.append(entry)
            return result_set
        except ldap.LDAPError, e:
            print e, branch_name

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

    def get_branches(self):
        try:
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
        except ldap.LDAPError, e:
            print e