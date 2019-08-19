# -*- coding: utf-8 -*-

from __future__ import absolute_import
import os
import click
import requests
import logging
import platform
from federated_aws_cli.config import parse_config
from federated_aws_cli.login import login
from federated_aws_cli import sts_conn
try:
    # This is optional and only provides more detailed debug messages
    from jose import jwt
except ImportError:
    jwt = None

ENV_VARIABLE_NAME_MAP = {
    "AccessKeyId": "AWS_ACCESS_KEY_ID",
    "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
    "SessionToken": "AWS_SESSION_TOKEN",
}

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_aws_env_variables(credentials):
    result = ""
    verb = "set" if platform.system() == "Windows" else "export"

    for key in [x for x in credentials if x in ENV_VARIABLE_NAME_MAP]:
        result += "{} {}={}\n".format(verb, ENV_VARIABLE_NAME_MAP[key], credentials[key])
    return result


@click.command()
@click.option(
    "-c",
    "--config-file",
    default=os.path.join(os.path.expanduser("~"), ".federated_aws_cli.yaml"),
    help="Relative path to config file",
    type=click.Path(exists=True))
@click.option("-r", "--role-arn", required=True, help="RoleARN to assume")
@click.option(
    "-o", "--output", default="envvar", type=click.Choice(["envvar", "sha1"]), help="How to output the AWS API keys"
)
@click.option("-v", "--verbose", is_flag=True, help="Print debugging messages")
def main(config_file, role_arn, output, verbose):
    """Fetch AWS API Keys using SSO web login"""
    if verbose:
        logger.setLevel(logging.DEBUG)

    # Parse config file
    config = parse_config(config_file)
    config["openid-configuration"] = requests.get(config["well_known_url"]).json()
    config["jwks"] = requests.get(config["openid-configuration"]["jwks_uri"]).json()
    logger.debug("JWKS : {}".format(config["jwks"]))

    logger.debug("Config : {}".format(config))

    tokens = login(
        config["openid-configuration"]["authorization_endpoint"],
        config["openid-configuration"]["token_endpoint"],
        config["client_id"],
        config["scope"],
    )

    logger.debug("ID token : {}".format(tokens["id_token"]))

    if jwt:
        id_token_dict = jwt.decode(
            token=tokens["id_token"],
            key=config["jwks"],
            audience=config["client_id"])
        logger.debug("ID token dict : {}".format(id_token_dict))

    credentials = sts_conn.get_credentials(tokens["id_token"], role_arn=role_arn)
    if not credentials:
        exit(1)

    logger.debug(credentials)

    if output == "envvar":
        print(get_aws_env_variables(credentials))


if __name__ == "__main__":
    main()
