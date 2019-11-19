import pwd
import os
import logging
from xml.etree import ElementTree

import requests

from .cache import read_sts_credentials, write_sts_credentials


logger = logging.getLogger(__name__)


def get_credentials(bearer_token, id_token_dict, role_arn):
    """Exchange a bearer token and IAM Role ARN for AWS API keys

    :param bearer_token: OpenID Connect ID token provided by IdP
    :param id_token_dict: Parsed bearer_token
    :param role_arn: AWS IAM Role ARN of the role to assume
    :return: dict : Dictionary of credential information
    """
    # Try to read the locally cached STS credentials
    credentials = read_sts_credentials(role_arn)

    if credentials is None:
        role_session_name = (
            id_token_dict['email']
            if 'email' in id_token_dict
            else id_token_dict['sub'].split('|')[-1])
        sts_url = "https://sts.amazonaws.com/"
        for duration_seconds in [43200, 3600]:  # 12 hours, 1 hour
            # First try to provision a session of 12 hours, then fall back to
            # 1 hour, the default max, if the 12 hour attempt fails. If that
            # 1 hour duration also fails, then error out
            parameters = {
                'Action': 'AssumeRoleWithWebIdentity',
                'DurationSeconds': duration_seconds,
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
            else:
                logger.debug('Session established for {} seconds'.format(duration_seconds))
                logger.debug('STS Call Response headers : {}'.format(resp.headers))
                logger.debug('STS Call Response : {}'.format(resp.text))
                break
        else:
            # No break was encountered so none of the requests returned success
            return None

        root = ElementTree.fromstring(resp.content)
        # Create a dictionary of the children of
        # AssumeRoleWithWebIdentityResult/Credentials and their values
        credentials = dict([(x.tag.split('}', 1)[-1], x.text) for x in root.find(
            './sts:AssumeRoleWithWebIdentityResult/sts:Credentials',
            {'sts': 'https://sts.amazonaws.com/doc/2011-06-15/'})])

        # Cache the STS credentials to disk
        write_sts_credentials(role_arn, credentials)

    return credentials
