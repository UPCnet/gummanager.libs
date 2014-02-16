import base64
import hashlib
import ldap
import ldap.modlist as modlist
import os


class LdapServer(object):
    def __init__(self, *args, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

        self.ldap_uri = '{server}:{port}'.format(**kwargs)
        self.leaf_dn = ''

    def connect(self):
        self.ld = ldap.initialize(self.ldap_uri)
        self.ld.simple_bind_s("{admin_cn},{base_dn}".format(**self.__dict__), self.admin_password)

    def disconnect(self):
        self.ld.unbind_s()

    def cd(self, dn):
        if dn == '/':
            self.leaf_dn = ''
        else:
            self.leaf_dn = dn

    @property
    def dn(self):
        base_dn = self.base_dn
        if self.leaf_dn:
            base_dn = '{},{}'.format(self.leaf_dn, self.base_dn)
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
            'cn': user_name,
            'sn': display_name,
            'userPassword': self.ssha(password)
        })

        self.ld.add_s(dn, ldif)

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

    def addBranch(self, branch_name):
        self.addOU(branch_name)
        self.cd('ou={}'.format(branch_name))
        self.addUser('ldap', 'LDAP Access User', 'secret')
        self.addUser('restricted', 'Restricted User', '{}secret'.format(branch_name))
        self.addGroup('Managers')
        self.addOU('groups')
        self.addOU('users')
