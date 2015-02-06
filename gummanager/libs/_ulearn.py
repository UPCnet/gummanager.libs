from gummanager.libs.utils import step_log, error_log, raising_error_log, success_log, RemoteConnection, padded_error, padded_success, progress_log, padded_log
from gummanager.libs.config_files import ULEARN_NGINX_ENTRY
from gummanager.libs._genweb import GenwebServer, Plone
from gummanager.libs.mixins import TokenHelper
from gummanager.libs.batch import read_users_file
from gummanager.libs.batch import read_subscriptions_file

import requests
from collections import Counter

from pyquery import PyQuery
from hashlib import sha1


class UlearnSite(Plone, TokenHelper):

    def get_settings(self):
        req = requests.get('{}/@@maxui-settings'.format(self.site_url), auth=self.auth)
        pq = PyQuery(req.content)
        inputs = pq('form input[type=hidden], form input[type=text]')

        settings = {}

        for inp in inputs:
            pqinput = PyQuery(inp)
            settings[pqinput.attr('name').split('.')[-1]] = pqinput.val()
        return settings

    def add_user(self, **user):
        new_username = user['username']
        add_user_url = '{}/api/people/{}'.format(self.site_url, new_username)

        site_settings = self.get_settings()
        response = requests.post(
            add_user_url,
            headers=self.oauth_headers(
                site_settings['max_restricted_username'],
                site_settings['max_restricted_token'],
            ),
            data=user,
            verify=False)

        if response.status_code in [200, 201]:
            try:
                response.json()
            except ValueError:
                # If no json colud be decoded, 99.99% that is the unauthorized Plone view
                # but it could be a crash
                return {'error': True, 'message': 'Unauthorized or server error'}
        else:
            return {'error': True, 'message': 'Server Error'}
        return response.json()

    def subscribe_users(self, **users):
        community_url = users.pop('url')
        community_hash = sha1(community_url).hexdigest()
        add_subscriptions_url = '{}/api/communities/{}/subscriptions'.format(self.site_url, community_hash)

        site_settings = self.get_settings()
        response = requests.post(
            add_subscriptions_url,
            headers=self.oauth_headers(
                site_settings['max_restricted_username'],
                site_settings['max_restricted_token'],
            ),
            data=users,
            verify=False)

        if response.status_code in [200, 201]:
            try:
                response.json()
            except ValueError:
                # If no json colud be decoded, 99.99% that is the unauthorized Plone view
                # but it could be a crash
                return {'error': True, 'message': 'Unauthorized or server error'}
        return response.json()

    def setup_max(self, max_name, oauth_name, ldap_branch):
        """
        """
        username = 'restricted'
        password = '{}secret'.format(ldap_branch)
        oauth_server = "https://oauth.upcnet.es/{}".format(oauth_name)
        user_token = self.get_token(oauth_server, username, password)
        if user_token is None:
            return error_log('Error on getting token for user "{}" on {}'.format(username, oauth_server))

        params = {
            "form.widgets.oauth_server": oauth_server,
            "form.widgets.oauth_grant_type": "password",
            "form.widgets.max_server": "https://max.upcnet.es/{}".format(max_name),
            "form.widgets.max_server_alias": "https://ulearn.upcnet.es/{}".format(self.plonesite),
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

    def __init__(self, *args, **kwargs):
        super(ULearnServer, self).__init__(*args, **kwargs)
        self.prefes = RemoteConnection(self.config.prefe_ssh_user, self.config.prefe_server)

    def reload_nginx_configuration(self):
        progress_log('Reloading nginx configuration')
        padded_log('Testing configuration')
        code, stdout = self.prefes.execute('/etc/init.d/nginx configtest')
        if code == 0 and 'done' in stdout:
            padded_success('Configuration test passed')
        else:
            padded_error('Configuration test failed')
            return None

        code, stdout = self.prefes.execute('/etc/init.d/nginx reload')
        if code == 0 and 'done' in stdout:
            padded_success('Nginx reloaded succesfully')
        else:
            padded_error('Error reloading nginx')
            return None

    def setup_nginx(self, site, max_url):

        nginx_params = {
            'instance_name': site.plonesite,
            'max_server': max_url,
            'mountpoint_id': site.mountpoint
        }
        nginxentry = ULEARN_NGINX_ENTRY.format(**nginx_params)

        success = self.prefes.put_file("{}/config/ulearn-instances/{}.conf".format(self.config.prefe_nginx_root, site.plonesite), nginxentry)

        if success:
            return success_log("Succesfully created {}/config/ulearn-instances/{}.conf".format(self.config.prefe_nginx_root, site.plonesite))
        else:
            return error_log('Error when generating nginx config file for ulean')

    def get_instance(self, environment, mountpoint, plonesite):
        site = UlearnSite(environment, mountpoint, plonesite, '', '')
        settings = site.get_settings()
        return settings

    def add_user(self, instance, user):
        """
        """
        pass

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

        # Look for repeated emails
        emails = [a['email'] for a in users]
        duplicates = [k for k, v in Counter(emails).items() if v > 1]
        if duplicates:
            raise Exception('Found duplicated emails: {}'.format(', '.join(duplicates)))

        # Look for users withuot password
        users_without_password = [a['username'] for a in users if a['password'].strip() == '']
        if users_without_password:
            raise Exception('Found users without password: {}'.format(', '.join(users_without_password)))

    # COMMANDS

    def batch_add_users(self, instance, usersfile):
        site = UlearnSite(
            self.get_environment(instance['environment']),
            instance['mountpoint'],
            instance['plonesite'])
        try:
            users = read_users_file(usersfile, required_fields=['username', 'fullname', 'email', 'password'])
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
            succeeded = site.add_user(**user)
            if not succeeded.get('error', False):
                yield success_log(succeeded['message'])
            else:
                yield error_log(succeeded['message'])

    def batch_subscribe_users(self, instance, subscriptionsfile):
        site = UlearnSite(
            self.get_environment(instance['environment']),
            instance['mountpoint'],
            instance['plonesite'])
        try:
            communities = read_subscriptions_file(subscriptionsfile, required_fields=['owners', 'readers', 'editors'])
        except Exception as exc:
            error_message = 'Error parsing subscriptionsfile file {}: {{}}'.format(subscriptionsfile)
            yield raising_error_log(error_message.format(exc.message))

        for community in communities:
            yield step_log('Subscribing users to {}'.format(community['url']))

            succeeded = site.subscribe_users(**community)
            if not succeeded.get('error', False):
                yield success_log(succeeded['message'])
            else:
                yield error_log(succeeded['message'])

    def new_instance(self, instance_name, environment, mountpoint, title, language, max_name, max_direct_url, oauth_name, ldap_branch, ldap_password, logecho):

        environment = self.get_environment(environment)
        site = UlearnSite(environment, mountpoint, instance_name, title, language, logecho)

        yield step_log('Creating Plone site')
        yield site.create(packages=['ulearn.core:default'])

        yield step_log('Setting up homepage')
        yield site.setup_homepage()

        yield step_log('Setting up ldap')
        yield site.setup_ldap(branch=ldap_branch, password=ldap_password)

        yield step_log('Setting up max')
        yield site.setup_max(max_name, oauth_name, ldap_branch)

        yield step_log('Rebuilding catalog')
        yield site.rebuild_catalog()

        yield step_log('Setting up nginx entry @ {}'.format(self.config.prefe_server))
        yield self.setup_nginx(site, max_direct_url)
