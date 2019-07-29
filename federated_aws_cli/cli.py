# -*- coding: utf-8 -*-

from __future__ import absolute_import
import click
import logging
from xdg.BaseDirectory import xdg_cache_home as XDG_CACHE_HOME
from jose import jwt  # This is optional so we can probably remove it and the code that uses it
from federated_aws_cli.config import parse_config
from federated_aws_cli.login import PkceLogin
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
    logger.debug("Using {} cache directory".format(XDG_CACHE_HOME))

    config = parse_config(config_file)
    logger.debug("Config : {}".format(config))

    pkce = PkceLogin(config["well_known_url"], config["client_id"], config["scope"])
    pkce.refresh_id_token()
    id_token_dict = jwt.decode(token=pkce.tokens["id_token"], key=pkce.jwks, audience=pkce.client_id)
    logger.debug("ID token dict : {}".format(id_token_dict))

    sts = sts_conn.StsCredentials(pkce.tokens["id_token"], role_arn)
    sts.refresh_credentials()

    if output == "envvar":
        print(sts.as_env_variables())
        print(pkce.as_env_variables())


if __name__ == "__main__":
    main()
