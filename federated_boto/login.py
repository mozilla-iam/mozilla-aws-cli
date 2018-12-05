import base64
import hashlib
import json
import requests
import secrets
import urllib
import urllib.parse
import webbrowser
import logging
import listener

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def base64_without_padding(data):
    # https://tools.ietf.org/html/rfc7636#appendix-A
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def generate_challenge(code_verifier):
    # https://tools.ietf.org/html/rfc7636#section-4.2
    return base64_without_padding(
        hashlib.sha256(code_verifier.encode()).digest())


def login(authorization_endpoint='https://auth.mozilla.auth0.com/authorize',
          token_endpoint='https://auth.mozilla.auth0.com/oauth/token',
          client_id='N7lULzWtfVUDGymwDs0yDEq6ZcwmFazj',
          audience='https://infosec.mozilla.org/aws-federated-cli'):
    """

    :param authorization_endpoint:
    :param token_endpoint:
    :param client_id:
    :param audience:
    :return:
    """
    code_verifier = base64_without_padding(secrets.token_bytes(32))
    code_challenge = generate_challenge(code_verifier)
    state = base64_without_padding(secrets.token_bytes(32))

    port = listener.get_available_port()
    redirect_uri = 'http://localhost:{}/redirect_uri'.format(port)

    url_parameters = {
        'audience': audience,
        'scope': 'profile',
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'state': state
    }
    url = '{}?{}'.format(
        authorization_endpoint,
        urllib.parse.urlencode(url_parameters))

    # Open the browser window to the login url
    # Start the listener
    logger.debug('About to spawn browser window to {}'.format(url))
    webbrowser.open_new(url)
    logger.debug('About to begin listener on port {}'.format(port))
    code, state, error_message = listener.get_code(port)

    if code is None:
        print("Error: session replay or similar attack in progress. Please "
              "log out of all connections.")
        exit(-1)

    if error_message is not None:
        print("An error occurred:")
        print(error_message)
        exit(-1)

    # Exchange the code for a token
    headers = {'Content-Type': 'application/json'}
    body = {'grant_type': 'authorization_code',
            'client_id': client_id,
            'code_verifier': code_verifier,
            'code': code,
            'audience': audience,
            'redirect_uri': redirect_uri}
    r = requests.post(token_endpoint, headers=headers, data=json.dumps(body))
    data = r.json()

    return data


def main():
    print(login())


if __name__ == "__main__":
    main()
