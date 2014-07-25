import requests
import json


class TokenHelper(object):

    @staticmethod
    def get_token(oauth_server, username, password):
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
