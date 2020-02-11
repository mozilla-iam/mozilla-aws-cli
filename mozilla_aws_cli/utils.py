import base64
import hashlib
import logging
import os
import signal
import sys


logger = logging.getLogger(__name__)
STSWarning = type("STSWarning", (Warning,), dict())


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


def role_arn_to_profile_name(role_arn, role_map):
    if not role_map:
        role_map = {}

    # get the plaintext role name
    role = role_arn.split(":")[-1].split("/")[-1]

    logger.debug("Role map is: {}".format(role_map))

    # Get the AWS account id from the role ARN, and then see if it's in the map
    account_id = role_arn.split(":")[4]
    account_id = role_map.get("aliases", {}).get(account_id, [account_id])[0]

    # such as infosec-somerole
    return "-".join([account_id, role])


def strip_xmlns(tag):
    # Turn tag like
    # "{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken" into
    # "SessionToken"
    return tag.split("}", maxsplit=1)[-1]
