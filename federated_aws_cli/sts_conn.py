import pwd
import os
import logging
from xml.etree import ElementTree

import requests

from .cache import read_sts_credentials, write_sts_credentials


logger = logging.getLogger(__name__)


def get_credentials(bearer_token, role_arn):
    """Exchange a bearer token and IAM Role ARN for AWS API keys

    :param bearer_token: OpenID Connect ID token provided by IdP
    :param role_arn: AWS IAM Role ARN of the role to assume
    :return: dict : Dictionary of credential information
    """
    # Try to read the locally cached STS credentials
    credentials = read_sts_credentials(role_arn)

    if credentials is None:
        local_username = pwd.getpwuid(os.getuid())[0]
        role_session_name = 'federated-aws-cli-{}'.format(local_username)
        sts_url = "https://sts.amazonaws.com/"
        duration_seconds = [3600, 43200]  # 1 hour, 12 hours
        while len(duration_seconds) > 0:
            # First try to provision a session of 12 hours, then fall back to
            # 1 hour, the default max, if the 12 hour attempt fails. If that
            # 1 hour duration also fails, then error out
            parameters = {
                'Action': 'AssumeRoleWithWebIdentity',
                'DurationSeconds': duration_seconds.pop(),
                'RoleArn': role_arn,
                'RoleSessionName': role_session_name,
                'WebIdentityToken': bearer_token,
                'Version': '2011-06-15'
            }

            # Call the STS API
            resp = requests.get(url=sts_url, params=parameters)
            if resp.status_code != requests.codes.ok:
                if 'The requested DurationSeconds exceeds the MaxSessionDuration set for this role' in resp.text:
                    continue
                logger.error('AWS STS Call failed {} : {}'.format(resp.status_code, resp.text))
                return None
            logger.debug('Session established for ')
            logger.debug('STS Call Response headers : {}'.format(resp.headers))
            logger.debug('STS Call Response : {}'.format(resp.text))

        root = ElementTree.fromstring(resp.content)
        # Create a dictionary of the children of
        # AssumeRoleWithWebIdentityResult/Credentials and their values
        credentials = dict([(x.tag.split('}', 1)[-1], x.text) for x in root.find(
            './sts:AssumeRoleWithWebIdentityResult/sts:Credentials',
            {'sts': 'https://sts.amazonaws.com/doc/2011-06-15/'})])

        # Cache the STS credentials to disk
        write_sts_credentials(role_arn, credentials)

    return credentials
