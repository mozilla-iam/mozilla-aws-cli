from __future__ import absolute_import
import base64
import hashlib
import json
import os
import requests
import requests_cache
import webbrowser
import logging

try:
    # P3
    from urllib.parse import urlencode
except ImportError:
    # P2 Compat
    from urllib import urlencode
from xdg import XDG_CACHE_HOME
from federated_aws_cli import listener

logging.basicConfig()
logger = logging.getLogger(__name__)
requests_cache.install_cache("{}/federated_aws_cli_cache".format(XDG_CACHE_HOME))


class PkceLogin:
    def __init__(self, well_known_url, client_id=None, scope="openid", port=None):
        """
        :param authorization_endpoint: URL of the OIDC authorization endpoint obtained from the discovery document
        :param token_endpoint: URL of the OIDC token endpoint obtained from the discovery document
        :param client_id: OIDC client_id of the native OIDC application
        :param scope: OIDC scopes of claims to request
        """
        self.well_known_url = well_known_url
        self.client_id = client_id
        self.scope = scope
        self.tokens = None
        self.port = port if port is not None else listener.get_available_port()
        self.redirect_uri = "http://localhost:{}/redirect_uri".format(self.port)

    def __deferred_init__(self):
        self.openid_configuration = requests.get(self.well_known_url).json()
        self.jwks = requests.get(self.openid_configuration["jwks_uri"]).json()
        self.authorization_endpoint = self.openid_configuration["authorization_endpoint"]
        self.token_endpoint = self.openid_configuration["token_endpoint"]
        self.code_verifier = self.base64_without_padding(os.urandom(32))
        self.code_challenge = self.generate_challenge(self.code_verifier)
        self.state = self.base64_without_padding(os.urandom(32))

    def base64_without_padding(self, data):
        # https://tools.ietf.org/html/rfc7636#appendix-A
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    def generate_challenge(self, code_verifier):
        # https://tools.ietf.org/html/rfc7636#section-4.2
        return self.base64_without_padding(hashlib.sha256(code_verifier.encode()).digest())

    def get_id_token(self):
        return self.get_wait_for_id_token()

    def get_wait_for_id_token(self):
        """
        Follow the PKCE auth flow by spawning a browser for the user to login,
        passing a redirect_uri that points to a localhost listener. Once ther user
        logs into the IdP in the browser, the IdP will redirect the user to the
        localhost listener, making the OIDC code available to the CLI. CLI then
        exchanges the code for an tokens with the IdP and returns the tokens

        :return: id token dict containing  {'access_token': '...', 'id_token': '...', 'expires_in': 86400, 'token_type': 'Bearer'}
        """
        self.__deferred_init__()
        url_parameters = {
            "scope": self.scope,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "state": self.state,
        }
        # We don't set audience here because Auth0 will set the audience on it's
        # own
        url = "{}?{}".format(self.authorization_endpoint, urlencode(url_parameters))

        # Open the browser window to the login url
        # Start the listener
        logger.debug("About to spawn browser window to {}".format(url))
        webbrowser.get("firefox").open(
            url
        )  # This specifies firefox to work around webbrowser.BackgroundBrowser sending stdout/stderr to the console :
        # https://github.com/python/cpython/blob/783b794a5e6ea3bbbaba45a18b9e03ac322b3bd4/Lib/webbrowser.py#L177-L181
        logger.debug("About to begin listener on port {}".format(self.port))
        code, response_state, error_message = listener.get_code(self.port)

        if code is None:
            logger.error("Something wrong happened, could not retrieve session data")
            exit(1)

        if self.state != response_state:
            logger.error("Error: State returned from IdP doesn't match state sent")
            exit(1)

        if error_message is not None:
            logger.error(error_message)
            exit(1)

        # Exchange the code for a token
        headers = {"Content-Type": "application/json"}
        body = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code_verifier": self.code_verifier,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        with requests_cache.disabled():
            r = requests.post(self.token_endpoint, headers=headers, data=json.dumps(body))
            data = json.loads(r.text)

        # Contains:
        # {'access_token': '...', 'id_token': '...', 'expires_in': 86400, 'token_type': 'Bearer'}
        self.tokens = data
        logger.debug("Got new tokens through PKCE")
        return self.tokens
