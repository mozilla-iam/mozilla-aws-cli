from __future__ import absolute_import
from jose import jwt
import json
import logging
import os
import platform
import time
import webbrowser

import requests

from . import sts_conn
from .cache import (
    read_id_token,
    write_aws_cli_credentials,
    write_aws_shared_credentials,
    write_id_token
)
from .listener import listen, port
from .role_picker import (
    get_aws_env_variables,
    get_roles_and_aliases,
)
from .utils import (
    base64_without_padding,
    exit_sigint,
    generate_challenge,
    role_arn_to_profile_name
)

try:
    # P3
    from urllib.parse import urlencode, urlunparse, urlparse
except ImportError:
    # P2 Compat
    from urllib import urlencode
    from urlparse import urlunparse, urlparse


logger = logging.getLogger(__name__)


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
        issuer_domain=None,
    ):

        # We use this for tracking various bits
        self.id = str(id(self))

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
        self.role = None
        self.role_arn = role_arn
        self.role_map = None

        # OIDC scopes of claims to request
        self.oidc_scope = scope if scope is not None else "openid"
        self.oidc_state = self.id + "-" + base64_without_padding(os.urandom(32))

        # URL of the OIDC token endpoint obtained from the discovery document
        self.token_endpoint = token_endpoint
        self.batch = batch
        self.web_console = web_console
        self.issuer_domain = issuer_domain

        # Whether or not we have opened a browser tab
        self.opened_tab = False

        # Whether we've gotten credentials via STS
        self.credentials = None

        # This used by the web application to poll the login state
        self.state = "pending"
        self.web_state = {
            "id": self.id,
        }

    def exit(self, message):
        print(message)

        if self.opened_tab:
            self.state = "error"
            self.web_state["message"] = message
            time.sleep(3600)

        exit_sigint()

    def login(self):
        """Follow the PKCE auth flow by spawning a browser for the user to
        login, passing a redirect_uri that points to a localhost listener. Once
        the user logs into the IdP in the browser, the IdP will redirect the
        user to the localhost listener, making the OIDC code available to the
        CLI. CLI then exchanges the code for an tokens with the IdP and returns
        the tokens

        :return: Nothing, as the callback will send SIGINT to terminate
        """
        self.state = "starting"
        self.redirect_uri = "http://localhost:{}/redirect_uri".format(port)

        token = read_id_token(self.openid_configuration.get("issuer"),
                              self.client_id,
                              self.jwks)

        if token is None or self.role_arn is None:
            self.state = "redirecting"
            url_parameters = {
                "scope": self.oidc_scope,
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "code_challenge": self.code_challenge,
                "code_challenge_method": "S256",
                "state": self.oidc_state,
            }

            logger.debug("{} (state), {} (code), {} (id)".format(url_parameters["state"],
                                                                 url_parameters["code_challenge"],
                                                                 id(self)))

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
            self.opened_tab = True

            # start up the listener, figuring out which port it ran on
            logger.debug("About to start listener running on port {}".format(port))
            listen(self)
        else:
            self.get_id_token(None, None, token=token)

    def get_id_token(self, code, state, token=None, **kwargs):
        """
        :param code: code GET paramater as sent by IdP
        :param state: state GET parameter as sent by IdP
        :param token: cached token (if available)
        :param kwargs: remaining optional arguments passed back to the redirect
                       URI. For example 'error' and 'error_description'
        :return:
        """
        if kwargs.get('error'):
            self.exit((
                "Received an error response from the identity provider in "
                "response to the /authorize request : {}".format(
                    kwargs.get('error_description'))
            ))

        if token is None:  # Callback from web listener
            self.state = "getting_id_token"

            if code is None:
                self.exit("Something wrong happened, could not retrieve session data")

            if self.oidc_state != state:
                logger.error("Mismatched state: {} (state) vs. {} (OIDC state) in {}".format(
                    state, self.oidc_state, id(self)
                ))
                self.exit("Error: State returned from IdP doesn't match state sent")

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

        # get the role map, either from cache or from the endpoint
        self.state = "getting_role_map"

        self.role_map = get_roles_and_aliases(
            endpoint=self.idtoken_for_roles_url,
            token=token["id_token"],
            key=self.jwks
        )

        if self.role_map is None:
            self.exit("Unable to retrieve role map. Shutting down.")

        logger.debug(
            'Roles and aliases are {}'.format(self.role_map))

        # TODO: Consider whether this needs to loop forever
        while self.credentials is None:
            # If we don't have a role ARN on the command line, we need to show
            # the role picker
            if self.role_arn is None and not self.batch:
                self.state = "role_picker"

                # Wait for the POST to /api/roles
                while not self.role_arn:
                    time.sleep(.05)

            # Use the cached credentials or retrieve them from STS
            self.state = "getting_sts_credentials"
            self.credentials = sts_conn.get_credentials(
                token["id_token"],
                id_token_dict,
                role_arn=self.role_arn
            )

            if self.credentials is None:
                token_vals = ([
                    id_token_dict[x] for x in id_token_dict
                    if x in ['amr', 'iss', 'aud']]
                    if jwt else ['unknown'] * 3)
                logger.error(
                    'AWS STS Call failed when attempting to assume role {} '
                    'with amr {} iss {} and aud {}'.format(
                        self.role_arn, *token_vals))
                logger.error(
                    'Unable to assume role {}. Please select a different '
                    'role.'.format(self.role_arn))

                if len(self.role_map.get("roles", [])) <= 1:
                    self.exit("Sorry, no valid roles available. Shutting down.")
                else:
                    self.role_map.get("roles", []).remove(self.role_arn)
                    self.role_arn = None
            if self.batch:
                break

        logger.debug(self.credentials)
        logger.debug("ID token : {}".format(token["id_token"]))

        # TODO: Create a global config object?
        if self.credentials is not None:
            profile_name = role_arn_to_profile_name(
                self.role_arn, self.role_map)
            verb = "set" if platform.system() == "Windows" else "export"
            if self.output == "envvar":
                print('echo "{}"'.format(self.role_arn))
                print(get_aws_env_variables(self.credentials))
            elif self.output == "shared":
                # Write the credentials
                path = write_aws_shared_credentials(
                    self.credentials,
                    self.role_arn,
                    self.role_map)
                if path:
                    print('echo "{}"'.format(self.role_arn))
                    print(
                        "{verb} AWS_PROFILE={profile_name}\n"
                        "{verb} AWS_SHARED_CREDENTIALS_FILE={path}".format(
                            path=path,
                            profile_name=profile_name,
                            verb=verb,
                        )
                    )
            elif self.output == "awscli":
                # Call into aws a bunch of times
                if write_aws_cli_credentials(self.credentials,
                                             self.role_arn,
                                             self.role_map):
                    print(
                        "{verb} AWS_PROFILE={profile_name}".format(
                            verb=verb,
                            profile_name=profile_name
                        ))

                else:
                    logger.error('Unable to write credentials with aws-cli.')

            if self.web_console:
                self.aws_federate()
                time.sleep(3600)

            # If we've opened a tab, we wait for it to terminate things
            if self.opened_tab:
                self.state = "finished"

                # Now we sleep until the web page shuts things down
                time.sleep(3600)

    def aws_federate(self):
        logger.debug("Attempting to open AWS console.")

        creds = {
            "sessionId": self.credentials["AccessKeyId"],
            "sessionKey": self.credentials["SecretAccessKey"],
            "sessionToken": self.credentials["SessionToken"],
        }

        query = urlencode({
            "Action": "getSigninToken",
            "Session": json.dumps(creds),
        })
        logger.debug("Web Console params: {}".format(query))

        url_tuple = urlparse('https://signin.aws.amazon.com/federation')
        url = urlunparse(url_tuple._replace(query=query))
        token = requests.get(url).json()

        account_id = self.role_arn.split(":")[4]
        role = self.role_arn.split(':')[5].split('/')[-1]
        issuer_url_query = urlencode({"account": account_id, "role": role})
        issuer_url = urlunparse(
            ('https', self.issuer_domain, '/', '', issuer_url_query, ''))

        query = urlencode({
            "Action": "login",
            "Destination": "https://console.aws.amazon.com/",
            "SigninToken": token["SigninToken"],
            "Issuer": issuer_url,
        })
        url = urlunparse(url_tuple._replace(query=query))

        logger.debug("Web browser console URL: {}".format(url))

        if self.opened_tab:
            self.state = "aws_federate"
            self.web_state["awsFederationUrl"] = url
            return url
        else:
            self.opened_tab = True
            webbrowser.open_new_tab(url)

            # Shut everything down if we're directly sending people to AWS
            exit_sigint()


login = Login()


def main():
    print(login.login())


if __name__ == "__main__":
    main()
