import requests
import pwd
import os
import logging
import platform
from dateutil import parser
from datetime import datetime

try:
    from datetime import timezone
except ImportError:
    # P2
    pass
from xml.etree import ElementTree

logging.basicConfig()
logger = logging.getLogger(__name__)


class StsCredentials:
    def __init__(self, bearer_token, role_arn):
        """
        :param bearer_token: OpenID Connect ID token provided by IdP
        :param role_arn: AWS IAM Role ARN of the role to assume
        """
        self.bearer_token = bearer_token
        self.role_arn = role_arn
        self.role_session_name = "federated-aws-cli-{}".format(pwd.getpwuid(os.getuid())[0])
        self.AccessKeyId = None
        self.SecretAccessKey = None
        self.SessionToken = None
        self.Expiration = None

    def as_env_variables(self):
        """
        :return: str: environment variables that can be used with AWS Boto
        """
        ENV_VARIABLE_NAME_MAP = {
            "AccessKeyId": "AWS_ACCESS_KEY_ID",
            "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
            "SessionToken": "AWS_SESSION_TOKEN",
        }
        self.refresh_credentials()

        result = ""
        verb = "set" if platform.system() == "Windows" else "export"

        for key in ENV_VARIABLE_NAME_MAP:
            result += "{} {}={}\n".format(verb, ENV_VARIABLE_NAME_MAP[key], self.__dict__[key])
        return result[:-1]

    def refresh_credentials(self, laytime=120):
        """
        Refresh credentials as necessary if expired
        :laytime: int: How many seconds of laytime between requests to get new credentials, when approaching the
        expiration window
        """
        if self.Expiration is None:
            logger.debug("We have no STS credentials, getting new ones")
            return self.get_credentials()

        # Instruct we base ourselves on UTC
        os.environ["TZ"] = "UTC"
        try:
            now = datetime.now(timezone.utc)
        except NameError:
            # P2
            now = datetime.now()
        exp = parser.parse(self.Expiration)
        diff = exp - now
        # Make this a timestamp
        ts = diff.total_seconds()

        if ts < laytime:
            logger.debug("Credentials are about to expire, getting new ones")
            return self.get_credentials

        logger.debug("Current credentials are still valid: {} {}".format(self.AccessKeyId, self.Expiration))

    def get_credentials(self):
        """
        Exchange a bearer token and IAM Role ARN for AWS API keys
        """
        sts_url = "https://sts.amazonaws.com/"
        parameters = {
            "Action": "AssumeRoleWithWebIdentity",
            "RoleArn": self.role_arn,
            "RoleSessionName": self.role_session_name,
            "WebIdentityToken": self.bearer_token,
            "Version": "2011-06-15",
        }

        # Call the STS API
        resp = requests.get(url=sts_url, params=parameters)
        if resp.status_code != requests.codes.ok:
            logger.error("AWS STS Call failed {} : {}".format(resp.status_code, resp.text))
            raise Exception("AWS STS Call failed")

        logger.debug("STS Call Response headers : {}".format(resp.headers))

        root = ElementTree.fromstring(resp.content)
        # Create a dictionary of the children of
        # AssumeRoleWithWebIdentityResult/Credentials and their values
        credentials = dict(
            [
                (x.tag.split("}", 1)[-1], x.text)
                for x in root.find(
                    "./sts:AssumeRoleWithWebIdentityResult/sts:Credentials",
                    {"sts": "https://sts.amazonaws.com/doc/2011-06-15/"},
                )
            ]
        )
        self.AccessKeyId = credentials.get("AccessKeyId")
        self.SecretAccessKey = credentials.get("SecretAccessKey")
        self.Expiration = credentials.get("Expiration")
        self.SessionToken = credentials.get("SessionToken")
