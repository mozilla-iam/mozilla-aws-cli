# -*- coding: utf-8 -*-

from __future__ import absolute_import
import os
import click
import requests
import logging
import platform
import yaml
import yaml.parser
from federated_aws_cli.login import login
from federated_aws_cli import sts_conn
from federated_aws_cli.get_role_arns import get_role_arns
try:
    # This is optional and only provides more detailed debug messages
    from jose import jwt
except ImportError:
    jwt = None


try:
    # Python 3
    FileNotFoundError
except NameError:
    # Python 2
    FileNotFoundError = IOError

ENV_VARIABLE_NAME_MAP = {
    "AccessKeyId": "AWS_ACCESS_KEY_ID",
    "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
    "SessionToken": "AWS_SESSION_TOKEN",
}

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('urllib3').propagate = False


def get_aws_env_variables(credentials):
    result = ""
    verb = "set" if platform.system() == "Windows" else "export"
    for key in [x for x in credentials if x in ENV_VARIABLE_NAME_MAP]:
        result += "{} {}={}\n".format(
            verb, ENV_VARIABLE_NAME_MAP[key], credentials[key])
    return result


def validate_arn(ctx, param, value):
    # arn:aws:iam::account-id:role/role-name
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
    required=True,
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

    if role_arn is None:

        role_arns = get_role_arns(
            endpoint=config["idtoken_for_roles_url"],
            token=tokens["id_token"],
            key=config["jwks"],
            audience=config["client_id"])
    credentials = sts_conn.get_credentials(
        tokens["id_token"], role_arn=role_arn)
    if not credentials:
        exit(1)

    logger.debug(credentials)

    if output == "envvar":
        print(get_aws_env_variables(credentials))


if __name__ == "__main__":
    main()
