from __future__ import absolute_import
import base64
import hashlib
import logging
import os
import signal
import webbrowser

import requests

from federated_aws_cli import sts_conn
from federated_aws_cli.listener import listen, port
from federated_aws_cli.role_picker import get_aws_env_variables, get_roles_and_aliases, show_role_picker


try:
    # P3
    from urllib.parse import urlencode
except ImportError:
    # P2 Compat
    from urllib import urlencode

try:
    # This is optional and only provides more detailed debug messages
    from jose import jwt
except ImportError:
    jwt = None


logger = logging.getLogger(__name__)


def base64_without_padding(data):
    # https://tools.ietf.org/html/rfc7636#appendix-A
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def generate_challenge(code_verifier):
    # https://tools.ietf.org/html/rfc7636#section-4.2
    return base64_without_padding(hashlib.sha256(code_verifier.encode()).digest())


class Login():
    # Maybe this would be better to unroll from config?
    def configure(
                  self,
                  authorization_endpoint="https://auth.mozilla.auth0.com/authorize",
                  client_id="",
                  idtoken_for_roles_url=None,
                  jwks=None,
                  openid_configuration=None,
                  output=None,
                  role_arn=None,
                  scope="openid",
                  token_endpoint="https://auth.mozilla.auth0.com/oauth/token",
                  ):

        # URL of the OIDC authorization endpoint obtained from the discovery document
        self.authorization_endpoint = authorization_endpoint

        # OIDC client_id of the native OIDC application
        self.client_id = client_id

        self.code_verifier = base64_without_padding(os.urandom(32))
        self.code_challenge = generate_challenge(self.code_verifier)
        self.idtoken_for_roles_url = idtoken_for_roles_url
        self.jwks = jwks
        self.openid_configuration = openid_configuration
        self.output = output
        self.role_arn = role_arn
        self.redirect_uri = "http://localhost:{}/redirect_uri".format(port)

        # OIDC scopes of claims to request
        self.scope = scope
        self.state = base64_without_padding(os.urandom(32))

        # URL of the OIDC token endpoint obtained from the discovery document
        self.token_endpoint = token_endpoint

    def login(self):
        """Follow the PKCE auth flow by spawning a browser for the user to login,
        passing a redirect_uri that points to a localhost listener. Once the user
        logs into the IdP in the browser, the IdP will redirect the user to the
        localhost listener, making the OIDC code available to the CLI. CLI then
        exchanges the code for an tokens with the IdP and returns the tokens

        :return: Nothing, as the callback will send SIGINT to terminate
        """
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
        url = "{}?{}".format(self.authorization_endpoint,
                             urlencode(url_parameters))

        # Open the browser window to the login url

        # Previously we needed to call webbrowser.get() passing 'firefox' as an argument to the get method
        # This was to work around webbrowser.BackgroundBrowser[1] sending the browsers stdout/stderr to the console.
        # That output to the console would then corrupt the intended script output meant to be eval'd. This issue doesn't
        # appear to be manifesting anymore and so we've set it back to the default of whatever browser the OS uses.
        # [1]: https://github.com/python/cpython/blob/783b794a5e6ea3bbbaba45a18b9e03ac322b3bd4/Lib/webbrowser.py#L177-L181
        logger.debug("About to spawn browser window to {}".format(url))
        webbrowser.get().open_new_tab(url)

        # start up the listener, figuring out which port it ran on
        logger.debug("About to start listener running on port {}".format(port))
        listen(self.callback)

    def callback(self, code, state):
        """
        :param code: code GET paramater as sent by IdP
        :param state: state GET parameter as sent by IdP
        :return:
        """
        if code is None:
            print("Something wrong happened, could not retrieve session data")
            exit(1)

        if self.state != state:
            print("Error: State returned from IdP doesn't match state sent")
            exit(1)

        # Exchange the code for a token
        headers = {
            "Content-Type": "application/json"
        }
        body = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code_verifier": self.code_verifier,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }

        token = requests.post(self.token_endpoint, headers=headers, json=body).json()

        logger.debug("Validating response from endpoint: {}".format(token))

        if jwt:
            id_token_dict = jwt.decode(
                token=token["id_token"],
                key=self.jwks,
                audience=self.client_id)
            logger.debug("ID token dict : {}".format(id_token_dict))

        if self.role_arn is None:
            roles_and_aliases = get_roles_and_aliases(
                endpoint=self.idtoken_for_roles_url,
                token=token["id_token"],
                key=self.jwks
            )
            logger.debug('Roles and aliases are {}'.format(roles_and_aliases))
            self.role_arn = show_role_picker(roles_and_aliases)
            logger.debug('Role ARN {} selected'.format(self.role_arn))

        if self.role_arn is None:
            logger.info('Exiting, no IAM Role ARN selected')
            os.kill(os.getpid(), signal.SIGINT)

        credentials = sts_conn.get_credentials(
            token["id_token"], role_arn=self.role_arn)

        logger.debug(credentials)
        logger.debug("ID token : {}".format(token["id_token"]))

        # TODO: Create a global config object?
        if self.output == "envvar":
            print(get_aws_env_variables(credentials))

        # Send the signal to kill the application
        logger.debug("Shutting down Flask")
        os.kill(os.getpid(), signal.SIGINT)

        return credentials is not None


login = Login()


def main():
    print(login.login())


if __name__ == "__main__":
    main()
