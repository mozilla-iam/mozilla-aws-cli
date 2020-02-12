import datetime
import logging
from xml.etree import ElementTree

import requests

from .cache import read_sts_credentials, write_sts_credentials
from .utils import STSWarning, strip_xmlns


CREDENTIAL_REQUEST_DURATIONS = (43200, 3600, 9000)  # 12 hours, 1 hour, 15 mins
logger = logging.getLogger(__name__)

# Create some exception classes
MalformedResponseWarning = type("MalformedResponseWarning", (Warning,), dict())


def get_credentials(bearer_token, id_token_dict, role_arn):
    """Exchange a bearer token and IAM Role ARN for AWS API keys

    :param bearer_token: OpenID Connect ID token provided by IdP
    :param id_token_dict: Parsed bearer_token
    :param role_arn: AWS IAM Role ARN of the role to assume
    :return: dict : Dictionary of credential information or None if the
        bearer_token can't be used to produce credentials
    """
    # Try to read the locally cached STS credentials
    credentials = read_sts_credentials(role_arn)

    if credentials is None:
        role_session_name = (
            id_token_dict["email"]
            if "email" in id_token_dict
            else id_token_dict["sub"].split("|")[-1])
        sts_url = "https://sts.amazonaws.com/"

        # First try to provision a session of 12 hours, then fall back to
        # 1 hour, the default max, if the 12 hour attempt fails. If that
        # 1 hour duration also fails, then fall back to the minimum of 15
        # minutes
        for duration_seconds in CREDENTIAL_REQUEST_DURATIONS:
            parameters = {
                "Action": "AssumeRoleWithWebIdentity",
                "DurationSeconds": duration_seconds,
                "RoleArn": role_arn,
                "RoleSessionName": role_session_name,
                "WebIdentityToken": bearer_token,
                "Version": "2011-06-15"
            }

            # Call the STS API
            try:
                resp = requests.get(url=sts_url, params=parameters)
                root_xml_element = ElementTree.fromstring(resp.content)
                logger.debug("The XML response is: {}".format(resp.content))
            except ElementTree.ParseError:
                raise MalformedResponseWarning(
                    "Unable to parse XML response to "
                    "AssumeRoleWithWebIdentity call")
            except requests.exceptions.ConnectionError as e:
                raise STSWarning(
                    "Unable to contact AWS STS for credentials: {}".format(e))
            if resp.status_code != requests.codes.ok:
                error_children = root_xml_element.find(
                    "./sts:Error",
                    {"sts": "https://sts.amazonaws.com/doc/2011-06-15/"})
                error = dict(
                    [(strip_xmlns(x.tag), x.text) for x in error_children])
                logger.debug(
                    "AWS STS Call failed {status} {Type} {Code} : "
                    "{Message}".format(status=resp.status_code, **error))
                if (error["Code"] == "ValidationError"
                        and error["Message"] ==
                        "The requested DurationSeconds exceeds the "
                        "MaxSessionDuration set for this role."):
                    continue
                else:
                    raise STSWarning(
                        error["Type"], error["Code"], error["Message"])
            else:
                logger.debug("Session established for {} seconds".format(
                    duration_seconds))
                logger.debug("STS Call Response headers : {}".format(
                    resp.headers))
                logger.debug("STS Call Response : {}".format(resp.text))
                break
        else:
            # No break was encountered so none of the requests returned success
            raise STSWarning(
                "Sender",
                "NoAcceptableDuration",
                "No DurationSeconds was found that did not exceed the MaxSessionDuration for the role")

        # Create a dictionary of the children of
        # AssumeRoleWithWebIdentityResult/Credentials and their values
        credential_children = root_xml_element.find(
            "./sts:AssumeRoleWithWebIdentityResult/sts:Credentials",
            {"sts": "https://sts.amazonaws.com/doc/2011-06-15/"})
        credentials = dict([
            (strip_xmlns(x.tag), x.text) for x in credential_children])
        if 'Expiration' in credentials:
            utc_time = datetime.datetime.strptime(
                credentials['Expiration'], "%Y-%m-%dT%H:%M:%SZ")
            epoch_time = int(
                (utc_time -
                 datetime.datetime.utcfromtimestamp(0)).total_seconds())
            credentials['ExpirationSeconds'] = epoch_time

        # Cache the STS credentials to disk
        write_sts_credentials(role_arn, credentials)

    return credentials
