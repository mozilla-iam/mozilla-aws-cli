from __future__ import absolute_import, print_function
from jose import jwt, JWTError
import json
import logging
import os
import sys
import time
import traceback
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
    output_set_env_vars,
    get_roles_and_aliases,
)
from .utils import (
    base64_without_padding,
    exit_sigint,
    generate_challenge,
    role_arn_to_profile_name,
    STSWarning
)

try:
    # P3
    from urllib.parse import urlencode, urlunparse, urlparse
except ImportError:
    # P2 Compat
    from urllib import urlencode
    from urlparse import urlunparse, urlparse


logger = logging.getLogger(__name__)
ENV_VARIABLE_NAME_MAP = {
    "AccessKeyId": "AWS_ACCESS_KEY_ID",
    "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
    "SessionToken": "AWS_SESSION_TOKEN",
}


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
        config=None,
        profile_name=None,
        role_arn=None,
        scope="openid",
        token_endpoint="https://auth.mozilla.auth0.com/oauth/token",
        web_console=False,
        issuer_domain=None,
        cache=True,
        print_url=False,
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
        self.config = {} if config is None else config
        self.idtoken_for_roles_url = idtoken_for_roles_url
        self.jwks = jwks
        self.openid_configuration = openid_configuration
        self.output = self.config.get("output", "envvar")
        self.print_role_arn = self.config.get("print_role_arn", True)
        self.redirect_uri = None
        self.role = None
        self.role_arn = role_arn
        self.role_map = None

        # OIDC scopes of claims to request
        self.oidc_scope = scope if scope is not None else "openid"
        self.oidc_state = self.id + "-" + base64_without_padding(
            os.urandom(32))

        # URL of the OIDC token endpoint obtained from the discovery document
        self.batch = batch
        self.token_endpoint = token_endpoint
        self.issuer_domain = issuer_domain

        # Whether or not we have opened a browser tab
        self.opened_tab = False

        # The ID Token returned from the identity provider
        self.token = None
        self.id_token_dict = None

        # Whether we've gotten credentials via STS
        self.credentials = None

        # This is how long we will wait to see if we can get the
        self.last_state_check = None
        self.max_sleep_no_state_check = 2  # seconds

        # Whether we should open the AWS web console or not and whether we
        # should print the URL to stdout
        self.print_url = print_url
        self.web_console = web_console

        # If we're using the AWS CLI output, what profile should we use
        self.profile_name = profile_name

        # Whether we should print the output map, which isn't used by
        # output that is meant to be consumed programmatically
        self.print_output_map = True

        # This used by the web application to poll the login state
        self.state = "pending"
        self.web_state = {
            "id": self.id,
        }
        self.cache = cache

    def exit(self, message):
        print(message, file=sys.stderr)

        if self.opened_tab:
            self.state = "error"
            self.web_state["message"] = message

    def login(self):
        """Follow the PKCE auth flow by spawning a browser for the user to
        login, passing a redirect_uri that points to a localhost listener. Once
        the user logs into the IdP in the browser, the IdP will redirect the
        user to the localhost listener, making the OIDC code available to the
        CLI. CLI then exchanges the code for an tokens with the IdP and returns
        the tokens

        :return: Whether or not the login succeeded
        """
        self.state = "starting"
        self.redirect_uri = "http://localhost:{}/redirect_uri".format(port)

        self.token = read_id_token(
            self.openid_configuration.get("issuer"),
            self.client_id,
            self.jwks)

        if self.token is not None and self.role_arn is not None:
            logger.debug(
                "We have a cached ID token and the role was passed as an "
                "argument")
            if self.validate_id_token() is None:
                # If validation failed, set token back to None
                self.token = None
            else:
                # The ID Token verifies
                self.get_role_map()
                result = self.exchange_token_for_credentials()
                if self.role_arn is None:
                    if self.batch:
                        self.exit(
                            "Unable to fetch AWS STS credentials with ID "
                            "token. Exiting due to batch mode.")
                        return False
                    else:
                        print(
                            "Unable to assume IAM role. Spawning web role "
                            "picker to pick a different role.",
                            file=sys.stderr)
                if result == "finished":
                    return True

        if self.token is not None and self.role_arn is None:
            logger.debug(
                "We have a cached ID token but either no role was passed on "
                "the command line or it wasn't valid. Show the role picker")
            self.state = "redirecting"
            url_parameters = {
                "state": self.oidc_state,
                "code": "this value is unused"
            }
            webbrowser.get().open_new_tab(
                "{}?{}".format(
                    self.redirect_uri,
                    urlencode(url_parameters)
                ))
            self.opened_tab = True
            logger.debug(
                "About to start listener running on port {}".format(port))
            listen(self)
        elif self.token is None or self.role_arn is None:
            logger.debug(
                "Either the cached ID token was invalid or missing and we "
                "need to get a new one, or the user passed no role_arn on the "
                "command line so we need to spawn the role picker")
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

            logger.debug(
                "{} (state), {} (code), {} (id)".format(
                    url_parameters["state"],
                    url_parameters["code_challenge"],
                    id(self)))

            # We don't set audience here because Auth0 will set the audience on
            # it's own
            url = "{}?{}".format(self.authorization_endpoint,
                                 urlencode(url_parameters))

            # Open the browser window to the login url

            # Previously we needed to call webbrowser.get() passing 'firefox'
            # as an argument to the get method. This was to work around
            # webbrowser.BackgroundBrowser[1] sending the browsers
            # stdout/stderr to the console. That output to the console would
            # then corrupt the intended script output meant to be eval'd. This
            # issue doesn't appear to be manifesting anymore and so we've set
            # it back to the default of whatever browser the OS uses.
            # [1]: https://github.com/python/cpython/blob/783b794a5e6ea3bbbaba45a18b9e03ac322b3bd4/Lib/webbrowser.py#L177-L181  # noqa
            logger.debug("About to spawn browser window to {}".format(url))
            webbrowser.get().open_new_tab(url)
            self.opened_tab = True

            # start up the listener, figuring out which port it ran on
            logger.debug(
                "About to start listener running on port {}".format(port))
            listen(self)
        return True

    def get_id_token(self, code=None, state=None, token=None, **kwargs):
        """
        :param code: code GET paramater as sent by IdP
        :param state: state GET parameter as sent by IdP
        :param token: cached token (if available)
        :param kwargs: remaining optional arguments passed back to the redirect
                       URI. For example 'error' and 'error_description'
        :return:
        """
        if kwargs.get("error"):
            self.exit((
                "Received an error response from the identity provider in "
                "response to the /authorize request : {}".format(
                    kwargs.get("error_description"))
            ))
            return False

        if self.token is None and token is None:  # Callback from web listener
            self.state = "getting_id_token"

            if code is None:
                self.exit("Something wrong happened, could not retrieve "
                          "session data")
                return False

            if self.oidc_state != state:
                logger.error(
                    "Mismatched state: {} (state) vs. {} (OIDC state) in "
                    "{}".format(state, self.oidc_state, id(self)))
                self.exit(
                    "Error: State returned from IdP doesn't match state sent")
                return False

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
            try:
                self.token = requests.post(
                    self.token_endpoint, headers=headers, json=body).json()
            except requests.exceptions.ConnectionError as e:
                self.exit("Unable to fetch a token from the identity provider "
                          ": {}".format(e))
                return False

            # attempt to cache the id token
            write_id_token(self.openid_configuration.get("issuer"),
                           self.client_id,
                           self.token)
        elif self.token is None:
            self.token = token
        return self.token

    def validate_id_token(self):
        # decode the token for logging purposes
        logger.debug(
            "Validating response from endpoint: {}".format(self.token))
        try:
            self.id_token_dict = jwt.decode(
                token=self.token["id_token"],
                key=self.jwks,
                audience=self.client_id)
        except JWTError as e:
            logger.error("ID Token failed validation : {}".format(e))
            return None
        logger.debug("ID token dict : {}".format(self.id_token_dict))
        return self.id_token_dict

    def get_role_map(self):
        # get the role map, either from cache or from the endpoint
        self.state = "getting_role_map"
        url = self.idtoken_for_roles_url
        self.role_map = get_roles_and_aliases(
            endpoint=url,
            token=self.token["id_token"],
            key=self.jwks,
            cache=self.cache
        )

        if self.role_map is None:
            self.exit("Unable to retrieve role map. Shutting down.")
            return False

        logger.debug(
            "Roles and aliases are {}".format(self.role_map))
        return self.role_map

    def exchange_token_for_credentials(self):
        # Use the cached credentials or retrieve them from STS
        self.state = "getting_sts_credentials"
        try:
            self.credentials = sts_conn.get_credentials(
                self.token["id_token"],
                self.id_token_dict,
                self.role_arn,
            )
            logger.debug(self.credentials)
            logger.debug("ID token : {}".format(self.token["id_token"]))
            self.print_output()
            return self.state
        except STSWarning as e:
            if len(e.args) > 1 and e.args[1] == "AccessDenied":
                # Not authorized to perform sts:AssumeRoleWithWebIdentity
                # Either that role doesn't exist or it exists but doesn't
                # permit the user because of the conditions
                # Either way, lets refresh the group role map in case it's out
                # of date
                logger.debug("Unable to assume role {}".format(self.role_arn))
                self.cache = False
                self.get_role_map()
                if self.batch:
                    self.exit(
                        "Unable to assume role. Shutting down due to batch "
                        "mode being enabled")
                    return "error"

                self.state = "role_picker"
                if self.role_arn in self.role_map.get("roles", []):
                    self.role_map.get("roles", []).remove(self.role_arn)
                self.role_arn = None
                if len(self.role_map.get("roles", [])) <= 1:
                    self.exit(
                        "Sorry, no valid roles available. Shutting down.")
                    return "error"
            elif len(e.args) > 1 and e.args[1] == "ExpiredTokenException":
                logger.debug(
                    "AWS says that the ID token is expired : {}".format(e[2]))
                self.token = None
                url_parameters = {
                    "scope": self.oidc_scope,
                    "response_type": "code",
                    "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id,
                    "code_challenge": self.code_challenge,
                    "code_challenge_method": "S256",
                    "state": self.oidc_state,
                }
                url = "{}?{}".format(self.authorization_endpoint,
                                     urlencode(url_parameters))
                self.state = "restart_auth"
                self.web_state["idpUrl"] = url
                return "restart_auth"
            else:
                self.exit("Unable to contact AWS : {}".format(e))
                return "error"
        except Exception:
            self.exit("Unable to contact AWS : {}".format("".join(traceback.format_exception(*sys.exc_info()))))
            return "error"

    def print_output(self):
        # TODO: Create a global config object?
        if self.credentials is not None:
            if self.profile_name is None:
                self.profile_name = role_arn_to_profile_name(
                    self.role_arn, self.role_map)
            output_map = {}
            if self.output == "envvar":
                output_map.update(
                    {ENV_VARIABLE_NAME_MAP[x]: self.credentials[x]
                     for x in self.credentials
                     if x in ENV_VARIABLE_NAME_MAP})
                output_map.update({
                    "AWS_PROFILE": None,
                    "AWS_SHARED_CREDENTIALS_FILE": None,
                    "MAWS_PROMPT": self.profile_name})
            elif self.output == "shared":
                # Write the credentials
                path = write_aws_shared_credentials(
                    self.profile_name,
                    self.credentials)
                if path:
                    output_map.update({
                        "AWS_PROFILE": self.profile_name,
                        "AWS_SHARED_CREDENTIALS_FILE": path,
                        "MAWS_PROMPT": self.profile_name})
                    output_map.update({
                        x: None for x in ENV_VARIABLE_NAME_MAP.values()})
            elif self.output == "awscli":
                # Call into aws a bunch of times
                if write_aws_cli_credentials(self.profile_name,
                                             self.credentials):
                    if self.profile_name != "default":
                        output_map.update({
                            "AWS_PROFILE": self.profile_name,
                            "AWS_SHARED_CREDENTIALS_FILE": None,
                            "MAWS_PROMPT": self.profile_name
                        })
                        output_map.update({
                            x: None for x in ENV_VARIABLE_NAME_MAP.values()})
                else:
                    logger.error("Unable to write credentials with aws-cli.")
            elif self.output == "boto":
                # this output can be used directly by boto3
                print(json.dumps({
                        "aws_access_key_id": self.credentials["AccessKeyId"],
                        "aws_secret_access_key": self.credentials["SecretAccessKey"],
                        "aws_session_token": self.credentials["SessionToken"]},
                    indent=2))
                self.print_output_map = False
            elif self.output == "js":
                # this output can be used directly by the AWS Javascript SDK
                print(json.dumps({
                        "accessKeyId": self.credentials["AccessKeyId"],
                        "secretAccessKey": self.credentials["SecretAccessKey"],
                        "sessionToken": self.credentials["SessionToken"]},
                    indent=2))
                self.print_output_map = False
            else:
                raise ValueError(
                    "Output setting unknown : {}".format(self.output))

            if 'ExpirationSeconds' in self.credentials:
                output_map['AWS_SESSION_EXPIRATION'] = self.credentials['ExpirationSeconds']

            message = "Environment variables set for role {}".format(
                self.role_arn) if self.print_role_arn else None

            if output_map and self.print_output_map:
                print(output_set_env_vars(output_map, message))

            if self.web_console or self.print_url:
                self.aws_federate()
            else:
                self.state = "finished"

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

        url_tuple = urlparse("https://signin.aws.amazon.com/federation")
        url = urlunparse(url_tuple._replace(query=query))
        try:
            token = requests.get(url).json()
        except requests.exceptions.ConnectionError as e:
            self.exit("Unable to contact AWS to open web console : {}".format(
                e))
            return None

        account_id = self.role_arn.split(":")[4]
        account_alias = self.role_map.get("aliases", {}).get(
            account_id, [account_id])[0]
        role = self.role_arn.split(":")[5].split("/")[-1]
        issuer_url_query = urlencode({"account": account_alias, "role": role})
        issuer_url = urlunparse(
            ("https", self.issuer_domain, "/", "", issuer_url_query, ""))

        query = urlencode({
            "Action": "login",
            "Destination": "https://console.aws.amazon.com/",
            "SigninToken": token["SigninToken"],
            "Issuer": issuer_url,
        })
        url = urlunparse(url_tuple._replace(query=query))

        logger.debug("Web browser console URL: {}".format(url))

        if self.print_url:
            print(url)
            self.state = "finished"
        elif self.opened_tab:
            self.state = "aws_federate"
            self.web_state["awsFederationUrl"] = url
        else:
            self.opened_tab = True
            webbrowser.open_new_tab(url)
            self.state = "finished"

        return url


login = Login()


def main():
    print(login.login())


if __name__ == "__main__":
    main()
