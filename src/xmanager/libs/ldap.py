from common import getConfig

import ldap
import ldap.modlist as modlist
import base64, getpass, hashlib, os
import sys


class LdapServer(object):
    def __init__(self, *args, **kwargs):
        for k,v in kwargs.items():
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
            'objectclass': ['top','organizationalUnit'],
            'ou': ou_name,
            'description': ou_name
            }
        )
        self.ld.add_s(dn, ldif)

    def ssha(self, password):

        salt = os.urandom(16)
        return '{ssha}' + base64.b64encode(hashlib.sha1(password + salt).digest() + salt)

    def addUser(self, user_name, display_name, password):
        dn = 'cn={},{}'.format(user_name, self.dn)

        ldif = modlist.addModlist({
            'objectclass': ['top','organizationalPerson', 'person', 'inetOrgPerson'],
            'cn': user_name,
            'sn': display_name,
            'userPassword': self.ssha(password)
            }
        )

        self.ld.add_s(dn, ldif)

    def addGroup(self, group_name, users=[]):
        dn = 'cn={},{}'.format(group_name, self.dn)

        members = []
        members.append('cn={},{}'.format('ldap', self.dn))

        ldif = modlist.addModlist({
            'objectclass': ['top','groupOfNames'],
            'cn': group_name,
            'member': members
            }
        )

        self.ld.add_s(dn, ldif)

def main():
    if len(sys.argv) <= 1:
        print 'new ldap ou name required'
        sys.exit(1)

    instance_name = sys.argv[1]

    ld = LdapServer(**getConfig('ldap'))    
    ld.connect()    
    ld.addOU(instance_name)
    ld.cd('ou={}'.format(instance_name))
    ld.addUser('ldap', 'LDAP Access User', 'connldapnexio')
    ld.addUser('restricted', 'Restricted User', '{}secret'.format(instance_name))
    ld.addGroup('Managers')
    ld.addOU('groups')
    ld.addOU('users')
    ld.disconnect()


if __name__ == "__main__":
    main()