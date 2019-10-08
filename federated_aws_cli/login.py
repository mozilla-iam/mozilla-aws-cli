from __future__ import absolute_import
from jose import jwt
import base64
import hashlib
import json
import logging
import os
import signal
import sys
import webbrowser

import requests

from federated_aws_cli import sts_conn
from federated_aws_cli.cache import (
    read_group_role_map,
    read_id_token,
    write_aws_cli_credentials,
    write_aws_shared_credentials,
    write_id_token
)
from federated_aws_cli.listener import listen, port
from federated_aws_cli.role_picker import (
    get_aws_env_variables,
    get_aws_shared_credentials,
    get_roles_and_aliases,
    NoPermittedRoles,
    show_role_picker
)

try:
    # P3
    from urllib.parse import quote_plus, urlencode
except ImportError:
    # P2 Compat
    from urllib import quote_plus, urlencode


logger = logging.getLogger(__name__)


def base64_without_padding(data):
    # https://tools.ietf.org/html/rfc7636#appendix-A
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def exit_sigint():
    # Close stdout/stderr before sending SIGINT, mostly to avoid `click` errors
    # See: https://github.com/mozilla-iam/federated-aws-cli/issues/88
    f = open(os.devnull, "w")
    sys.stdout = sys.stderr = f

    os.kill(os.getpid(), signal.SIGINT)


def generate_challenge(code_verifier):
    # https://tools.ietf.org/html/rfc7636#section-4.2
    return base64_without_padding(
        hashlib.sha256(code_verifier.encode()).digest())


def open_web_console(credentials):
    logger.debug("Attempting to open AWS console.")

    creds = {
        "sessionId": credentials["AccessKeyId"],
        "sessionKey": credentials["SecretAccessKey"],
        "sessionToken": credentials["SessionToken"],
    }

    params = urlencode({
        "Action": "getSigninToken",
        "Session": json.dumps({
            "sessionId": credentials["AccessKeyId"],
            "sessionKey": credentials["SecretAccessKey"],
            "sessionToken": credentials["SessionToken"]
        }),
    })

    logger.debug("Web Console params: {}".format(params))

    url = "https://signin.aws.amazon.com/federation?Action=getSigninToken"
    url += "&Session={}".format(quote_plus(json.dumps(creds)))

    token = requests.get(url).json()

    url = "https://signin.aws.amazon.com/federation?Action=login"
    url += "&Destination=" + quote_plus("https://console.aws.amazon.com/")
    url += "&SigninToken=" + token["SigninToken"]

    logger.debug("Web browser console URL: {}".format(url))

    webbrowser.open(url)


class Login:
    # Maybe this would be better to unroll from config?
    def __init__(
        self,
        authorization_endpoint="https://auth.mozilla.auth0.com/authorize",
        batch=False,
        client_id="",
        idtoken_for_roles_url=None,
        jwks=None,
        openid_configuration=None,
        output=None,
        role_arn=None,
        scope="openid",
        token_endpoint="https://auth.mozilla.auth0.com/oauth/token",
        web_console=False,
    ):

        # URL of the OIDC authorization endpoint obtained from the discovery
        # document
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
        self.batch = batch
        self.web_console = web_console

    def login(self):
        """Follow the PKCE auth flow by spawning a browser for the user to
        login, passing a redirect_uri that points to a localhost listener. Once
        the user logs into the IdP in the browser, the IdP will redirect the
        user to the localhost listener, making the OIDC code available to the
        CLI. CLI then exchanges the code for an tokens with the IdP and returns
        the tokens

        :return: Nothing, as the callback will send SIGINT to terminate
        """
        token = read_id_token(self.openid_configuration.get("issuer"),
                              self.client_id,
                              self.jwks)

        if token is None:
            url_parameters = {
                "scope": self.scope,
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "code_challenge": self.code_challenge,
                "code_challenge_method": "S256",
                "state": self.state,
            }

            # We don't set audience here because Auth0 will set the audience on
            # it's own
            url = "{}?{}".format(self.authorization_endpoint,
                                 urlencode(url_parameters))

            # Open the browser window to the login url

            # Previously we needed to call webbrowser.get() passing 'firefox' as an
            # argument to the get method. This was to work around
            # webbrowser.BackgroundBrowser[1] sending the browsers stdout/stderr to
            # the console. That output to the console would then corrupt the
            # intended script output meant to be eval'd. This issue doesn't appear
            # to be manifesting anymore and so we've set it back to the default of
            # whatever browser the OS uses.
            # [1]: https://github.com/python/cpython/blob/783b794a5e6ea3bbbaba45a18b9e03ac322b3bd4/Lib/webbrowser.py#L177-L181  # noqa
            logger.debug("About to spawn browser window to {}".format(url))
            webbrowser.get().open_new_tab(url)

            # start up the listener, figuring out which port it ran on
            logger.debug("About to start listener running on port {}".format(port))
            listen(self.callback)
        else:
            self.callback(None, None, token=token)

    def callback(self, code, state, token=None, **kwargs):
        """
        :param code: code GET paramater as sent by IdP
        :param state: state GET parameter as sent by IdP
        :param token: cached token (if available)
        :param kwargs: remaining optional arguments passed back to the redirect
                       URI. For example 'error' and 'error_description'
        :return:
        """
        if kwargs.get('error'):
            print(
                "Received an error response from the identity provider in "
                "response to the /authorize request : {}".format(
                    kwargs.get('error_description')))
            exit_sigint()

        if token is None:  # Callback from web listener
            if code is None:
                print("Something wrong happened, could not retrieve session data")
                exit_sigint()

            if self.state != state:
                print("Error: State returned from IdP doesn't match state sent")
                exit_sigint()

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

            logger.debug(
                "POSTing to token endpoint to exchange code for id_token: "
                "{}".format(body))
            token = requests.post(
                self.token_endpoint, headers=headers, json=body).json()

            # attempt to cache the id token
            write_id_token(self.openid_configuration.get("issuer"),
                           self.client_id,
                           token)

        # decode the token for logging purposes
        logger.debug("Validating response from endpoint: {}".format(token))
        id_token_dict = jwt.decode(
            token=token["id_token"],
            key=self.jwks,
            audience=self.client_id)
        logger.debug("ID token dict : {}".format(id_token_dict))

        credentials = message = None
        while credentials is None:
            roles_and_aliases = get_roles_and_aliases(
                endpoint=self.idtoken_for_roles_url,
                token=token["id_token"],
                key=self.jwks
            )
            logger.debug(
                'Roles and aliases are {}'.format(roles_and_aliases))

            # If we don't have a role ARN on the command line, we need to show
            # the role picker
            if self.role_arn is None and not self.batch:
                try:
                    self.role_arn = show_role_picker(
                        roles_and_aliases, message)
                except NoPermittedRoles as e:
                    logger.error(e)
                    exit_sigint()
                logger.debug('Role ARN {} selected'.format(self.role_arn))

            # If they somehow exit out of the role picker or there aren't
            # any choices
            if self.role_arn is None:
                logger.info('Exiting, no IAM Role ARN selected')
                exit_sigint()

            # Use the cached credentials or retrieve them from STS
            credentials = sts_conn.get_credentials(
                token["id_token"],
                role_arn=self.role_arn
            )

            if credentials is None:
                token_vals = ([
                    id_token_dict[x] for x in id_token_dict
                    if x in ['amr', 'iss', 'aud']]
                    if jwt else ['unknown'] * 3)
                logger.error(
                    'AWS STS Call failed when attempting to assume role {} '
                    'with amr {} iss {} and aud {}'.format(
                        self.role_arn, *token_vals))
                message = (
                    'Unable to assume role {}. Please select a different '
                    'role.'.format(self.role_arn))
                self.role_arn = None
            if self.batch:
                break

        logger.debug(credentials)
        logger.debug("ID token : {}".format(token["id_token"]))

        # TODO: Create a global config object?
        if credentials is not None:
            role_map = read_group_role_map(self.idtoken_for_roles_url)

            if self.output == "envvar":
                print('echo "{}"'.format(self.role_arn))
                print(get_aws_env_variables(credentials))
            elif self.output == "shared":
                # Write the credentials
                path = write_aws_shared_credentials(credentials,
                                                    self.role_arn,
                                                    role_map)

                if path:
                    print('echo "{}"'.format(self.role_arn))
                    print(get_aws_shared_credentials(path))
            elif self.output == "awscli":
                # Call into aws a bunch of times
                if write_aws_cli_credentials(credentials,
                                             self.role_arn,
                                             role_map):
                    print('Successfully set credentials with aws-cli.')
                else:
                    logger.error('Unable to write credentials with aws-cli.')

            if self.web_console:
                open_web_console(credentials)

        # Send the signal to kill the application
        logger.debug("Shutting down Flask")
        exit_sigint()

        return credentials is not None


login = Login()


def main():
    print(login.login())


if __name__ == "__main__":
    main()
