# -*- coding: utf-8 -*-

from __future__ import absolute_import
from federated_aws_cli.login import login
import os
import click
import requests
import logging
import yaml
import yaml.parser


try:
    # Python 3
    FileNotFoundError
except NameError:
    # Python 2
    FileNotFoundError = IOError


logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('urllib3').propagate = False


def validate_arn(ctx, param, value):
    # arn:aws:iam::account-id:role/role-name
    if value is None:
        return None
    elements = value.split(':')
    if (len(elements) != 6 or elements[0] != 'arn' or elements[2] != 'iam'
            or not elements[5].startswith('role/')):
        raise click.BadParameter('Role ARN {} is not a valid ARN'.format(
            value))
    else:
        return value


def validate_config_file(ctx, param, value):
    try:
        with open(os.path.expanduser(value), "r") as stream:
            result = yaml.load(stream, Loader=yaml.SafeLoader)
    except FileNotFoundError:
        raise click.BadParameter('Config file {} not found'.format(value))
    except yaml.parser.ParserError:
        raise click.BadParameter(
            'Config file {} is not valid YAML'.format(value))
    missing_settings = (
        {'well_known_url', 'client_id', 'scope'} - set(result.keys()))
    if missing_settings:
        raise click.BadParameter(
            '{} setting{} are missing from the config file {}'.format(
                ', '.join(missing_settings),
                's' if len(missing_settings) > 1 else '',
                value))
    return result


@click.command()
@click.option(
    "-c",
    "--config",
    default=os.path.join("~", ".federated_aws_cli.yaml"),
    help="Relative path to config file",
    callback=validate_config_file)
@click.option(
    "-r",
    "--role-arn",
    help="AWS IAM Role ARN to assume",
    callback=validate_arn)
@click.option(
    "-o",
    "--output",
    default="envvar",
    type=click.Choice(["envvar", "sha1"]),
    help="How to output the AWS API keys"
)
@click.option("-v", "--verbose", is_flag=True, help="Print debugging messages")
def main(config, role_arn, output, verbose):
    """Fetch AWS API Keys using SSO web login"""
    if verbose:
        logger.setLevel(logging.DEBUG)

    config["openid-configuration"] = requests.get(config["well_known_url"]).json()
    config["jwks"] = requests.get(config["openid-configuration"]["jwks_uri"]).json()

    logger.debug("JWKS : {}".format(config["jwks"]))
    logger.debug("Config : {}".format(config))

    # Instantiate a login object, and begin login process
    login.configure(
        authorization_endpoint=config["openid-configuration"]["authorization_endpoint"],
        client_id=config["client_id"],
        idtoken_for_roles_url=config["idtoken_for_roles_url"],
        jwks=config["jwks"],
        openid_configuration=config["openid-configuration"],
        output=output,
        role_arn=role_arn,
        scope=config["scope"],
        token_endpoint=config["openid-configuration"]["token_endpoint"],
    )

    login.login()


if __name__ == "__main__":
    main()
