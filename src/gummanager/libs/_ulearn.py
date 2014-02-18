from gummanager.libs.ports import GENWEB_ZOPE_CLIENT_BASE_PORT
from gummanager.libs.utils import padded_error
from gummanager.libs._genweb import GenwebServer
import requests


class ULearnServer(GenwebServer):
    _remote_config_files = {}

    def new_instance(self, instance_name):

        siteid = instance_name
        environment = self.environments[0]
        title = siteid.capitalize()
        language = 'ca'
        mountpoint = '2'
        ldap_branch = 'switchmed'

        # Check if site exists

        AUTH = (environment['admin_username'], environment['admin_password'])

        genweb_base_url = 'http://{}:{}'.format(
            environment['server'],
            GENWEB_ZOPE_CLIENT_BASE_PORT + 1
        )

        #Create Plone Site
        print "Creating Plone Site"
        params = {
            "site_id": siteid,
            "title": title,
            "default_language": language,
            "setup_content:boolean": True,
            "extension_ids:list": [
                'plonetheme.classic:default',
                'plonetheme.sunburst:default',
                'ulearn.core:default'
            ],
            "form.submitted:boolean": True,
            "submit": "Crear lloc Plone"
        }

        manage_plone_url = '{}/{}/{}/manage'.format(genweb_base_url, mountpoint, siteid)

        req = requests.post('%s/%s/@@plone-addsite' % (genweb_base_url, mountpoint), params, auth=AUTH)
        if req.status_code not in [302, 200]:
            padded_error('Hi ha hagut algun error al afegir el plone a <a href="{}">{}</a>. Ja existeix?'.format(manage_plone_url, manage_plone_url))

        site_url = '{}/{}/{}'.format(genweb_base_url, mountpoint, siteid)

        setup_view_url = '{}/setuphomepage'.format(site_url)
        req = requests.get(setup_view_url, auth=AUTH,)

        setup_view_url = '{}/setupldapexterns'.format(site_url)
        req = requests.get(setup_view_url, auth=AUTH,)

        ldap_params = {
            'title': '{}-LDAP'.format(ldap_branch.upper()),
            'login_attr': 'cn',
            'uid_attr': 'cn',
            'rdn_attr': 'cn',
            'users_base': 'ou=users,ou={},dc=upcnet,dc=es'.format(ldap_branch),
            'users_scope:int': '2',
            'local_groups:int': '0',
            'implicit_mapping:int': '0',
            'groups_base': 'ou=groups,ou={},dc=upcnet,dc=es'.format(ldap_branch),
            'groups_scope:int': '2',
            'binduid:string': 'cn=ldap,ou={},dc=upcnet,dc=es'.format(ldap_branch),
            'bindpwd:string': 'secret',
            'binduid_usage:int': '1',
            'obj_classes': 'top,person,inetOrgPerson',
            'extra_user_filter': '',
            'encryption': 'SSHA',
            'roles': 'Authenticated,Member'
        }
        ldap_setup_url = '{}/acl_users/ldapexterns/acl_users/manage_edit'.format(site_url)
        req = requests.post(ldap_setup_url, ldap_params, auth=AUTH)
