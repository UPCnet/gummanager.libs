from gummanager.libs.utils import step_log, error_log, success_log
from gummanager.libs._genweb import GenwebServer, Plone
import requests
import json


class UlearnSite(Plone):

    def get_token(self, oauth_server, username, password):
        payload = {"grant_type": 'password',
                   "client_id": 'MAX',
                   "scope": 'widgetcli',
                   "username": username,
                   "password": password
                   }

        req = requests.post('{0}/token'.format(oauth_server), data=payload, verify=False)
        response = json.loads(req.text)
        if req.status_code == 200:
            token = response.get("access_token", False)
            # Fallback to legacy oauth server
            if not token:
                token = response.get("oauth_token")
            return token
        else:
            return None

    def setup_max(self, instance_name):
        """
        """
        username = 'restricted'
        password = '{}secret'.format(instance_name)
        oauth_server = "https://oauth.upcnet.es/{}".format(instance_name)
        user_token = self.get_token(oauth_server, username, password)
        if user_token is None:
            return error_log('Error on getting token for user "{}" on {}'.format(username, oauth_server))

        params = {
            "form.widgets.oauth_server": oauth_server,
            "form.widgets.oauth_grant_type": "password",
            "form.widgets.max_server": "https://max.upcnet.es/{}".format(instance_name),
            "form.widgets.max_server_alias": "https://ulearn.upcnet.es/{}".format(instance_name),
            "form.widgets.max_app_username": "appusername",
            "form.widgets.max_app_token": "",
            "form.widgets.max_restricted_username": username,
            "form.widgets.max_restricted_token": user_token,
            "form.buttons.save": "Save",
        }
        req = requests.post('{}/@@maxui-settings'.format(self.site_url), data=params, auth=self.auth)

        if req.status_code not in [302, 200, 204, 201]:
            return error_log('Error on configuring max settings'.format(self.site_url))
        else:
            return success_log('Successfully configured max settings'.format(self.site_url))


class ULearnServer(GenwebServer):
    _remote_config_files = {}

    def new_instance(self, instance_name, environment, mountpoint, title, language, ldap_branch):

        environment = self.get_environment(environment)

        site = UlearnSite(environment, mountpoint, instance_name, title, language)

        yield step_log('Creating Plone site')
        yield site.create(packages=['ulearn.core:default'])

        yield step_log('Setting up homepage')
        yield site.setup_homepage()

        yield step_log('Setting up ldap')
        yield site.setup_ldap(branch=ldap_branch)

        yield step_log('Setting up max')
        yield site.setup_max(ldap_branch)
