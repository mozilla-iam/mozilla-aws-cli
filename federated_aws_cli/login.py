from __future__ import absolute_import
import base64
import hashlib
import json
import os
import requests
import webbrowser
import logging

try:
    # P3
    from urllib.parse import urlencode
except ImportError:
    # P2 Compat
    from urllib import urlencode
from federated_aws_cli import listener

logging.basicConfig()
logger = logging.getLogger(__name__)


def base64_without_padding(data):
    # https://tools.ietf.org/html/rfc7636#appendix-A
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def generate_challenge(code_verifier):
    # https://tools.ietf.org/html/rfc7636#section-4.2
    return base64_without_padding(hashlib.sha256(code_verifier.encode()).digest())


def login(
    authorization_endpoint="https://auth.mozilla.auth0.com/authorize",
    token_endpoint="https://auth.mozilla.auth0.com/oauth/token",
    client_id="",
    scope="openid",
):
    """Follow the PKCE auth flow by spawning a browser for the user to login,
    passing a redirect_uri that points to a localhost listener. Once ther user
    logs into the IdP in the browser, the IdP will redirect the user to the
    localhost listener, making the OIDC code available to the CLI. CLI then
    exchanges the code for an tokens with the IdP and returns the tokens

    :param authorization_endpoint: URL of the OIDC authorization endpoint obtained from the discovery document
    :param token_endpoint: URL of the OIDC token endpoint obtained from the discovery document
    :param client_id: OIDC client_id of the native OIDC application
    :param scope: OIDC scopes of claims to request
    :return:
    """
    code_verifier = base64_without_padding(os.urandom(32))
    code_challenge = generate_challenge(code_verifier)
    state = base64_without_padding(os.urandom(32))

    port = listener.get_available_port()
    redirect_uri = "http://localhost:{}/redirect_uri".format(port)

    url_parameters = {
        "scope": scope,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    # We don't set audience here because Auth0 will set the audience on it's
    # own
    url = "{}?{}".format(authorization_endpoint, urlencode(url_parameters))

    # Open the browser window to the login url
    # Start the listener
    logger.debug("About to spawn browser window to {}".format(url))
    webbrowser.get("firefox").open(
        url
    )  # This specifies firefox to work around webbrowser.BackgroundBrowser sending stdout/stderr to the console :
    # https://github.com/python/cpython/blob/783b794a5e6ea3bbbaba45a18b9e03ac322b3bd4/Lib/webbrowser.py#L177-L181
    logger.debug("About to begin listener on port {}".format(port))
    code, response_state, error_message = listener.get_code(port)

    if code is None:
        print("Something wrong happened, could not retrieve session data")
        exit(1)

    if state != response_state:
        print("Error: State returned from IdP doesn't match state sent")
        exit(1)

    if error_message is not None:
        print("An error occurred:")
        print(error_message)
        exit(1)

    # Exchange the code for a token
    headers = {"Content-Type": "application/json"}
    body = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code_verifier": code_verifier,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    r = requests.post(token_endpoint, headers=headers, data=json.dumps(body))
    data = json.loads(r.text)

    return data


def main():
    print(login())


if __name__ == "__main__":
    main()
