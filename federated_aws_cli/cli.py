from __future__ import absolute_import
import os
import logging

import click
import requests
import sys
import yaml
import yaml.parser

from federated_aws_cli.login import Login


if sys.version_info[0] >= 3:
    basestring = str
else:
    FileNotFoundError = IOError


logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.ERROR)
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


def validate_config_file(ctx, param, filenames):
    if isinstance(filenames, basestring):
        filenames = [filenames]

    if not any([os.path.exists(path) for path in filenames]):
        raise click.BadParameter('Config files {} not found'.format(" ".join(filenames)))

    result = {}
    for filename in filenames:
        try:
            with open(filename, "r") as stream:
                # guard against empty files
                results = yaml.load(stream, Loader=yaml.SafeLoader)

                if results is not None:
                    result.update(results)
        except FileNotFoundError:
            pass
        except (yaml.parser.ParserError, yaml.parser.ScannerError):
            raise click.BadParameter(
                'Config file {} is not valid YAML'.format(filename))

    missing_settings = (
        {'well_known_url', 'client_id', 'scope'} - set(result.keys()))

    if missing_settings:
        raise click.BadParameter(
            '{} setting{} are missing from the config files {}'.format(
                ', '.join(missing_settings),
                's' if len(missing_settings) > 1 else '',
                " ".join(filenames)))

    return result


@click.command()
@click.option(
    "-c",
    "--config",
    # TODO: Support Windows
    # TODO: Rename to something much better
    default=[
        os.path.join("/etc", "federated_aws_cli.yaml"),
        os.path.join(os.path.expanduser("~"), ".federated_aws_cli", "config.yaml"),
    ],
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
@click.option("-b", "--batch", is_flag=True, help="Run non-interactively")
@click.option("-v", "--verbose", is_flag=True, help="Print debugging messages")
def main(config, role_arn, output, verbose, batch):
    """Fetch AWS API Keys using SSO web login"""
    if verbose:
        logger.setLevel(logging.DEBUG)

    config["openid-configuration"] = requests.get(config["well_known_url"]).json()
    config["jwks"] = requests.get(config["openid-configuration"]["jwks_uri"]).json()

    logger.debug("JWKS : {}".format(config["jwks"]))
    logger.debug("Config : {}".format(config))

    # Instantiate a login object, and begin login process
    login = Login(
        authorization_endpoint=config["openid-configuration"][
            "authorization_endpoint"],
        client_id=config["client_id"],
        idtoken_for_roles_url=config["idtoken_for_roles_url"],
        jwks=config["jwks"],
        openid_configuration=config["openid-configuration"],
        output=output,
        role_arn=role_arn,
        scope=config["scope"],
        token_endpoint=config["openid-configuration"]["token_endpoint"],
        batch=batch
    )

    login.login()


if __name__ == "__main__":
    main()
