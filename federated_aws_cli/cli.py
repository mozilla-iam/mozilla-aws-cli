# -*- coding: utf-8 -*-

from __future__ import absolute_import
import click
import requests
import logging
import platform
from jose import jwt  # This is optional so we can probably remove it and the code that uses it
from federated_aws_cli.config import parse_config
from federated_aws_cli.login import login
from federated_aws_cli import sts_conn


logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)


@click.command()
@click.option("-c", "--config-file", default="config.yaml", help="Relative path to config file")
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

    id_token_dict = jwt.decode(token=tokens["id_token"], key=config["jwks"], audience=config["client_id"])
    logger.debug("ID token dict : {}".format(id_token_dict))

    sts = sts_conn.StsCredentials(tokens["id_token"], role_arn)
    sts.refresh_credentials()

    if output == "envvar":
        print(sts.as_env_variables())


if __name__ == "__main__":
    main()
