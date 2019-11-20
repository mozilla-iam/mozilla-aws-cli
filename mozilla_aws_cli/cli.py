from __future__ import absolute_import
from distutils.spawn import find_executable
import os
import logging

import click
import requests
import sys

from .cache import disable_caching
from .config import DOT_DIR
from .login import Login

try:
    import mozilla_aws_cli_config
except ImportError:
    # There is no overriding configuration package that implements the
    # "mozilla_aws_cli_config" module. Use the normal config acquisition methods
    mozilla_aws_cli_config = None

if sys.version_info[0] >= 3:
    import configparser
    basestring = str
else:
    FileNotFoundError = IOError
    import ConfigParser as configparser


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


def validate_awscli_exists(ctx, param, value):
    if value.lower() == 'awscli' and not find_executable('aws'):
        raise click.BadParameter('AWS CLI is not detected on local system.')

    return value


def validate_config_file(ctx, param, filenames):
    if isinstance(filenames, basestring):
        filenames = [filenames]

    if (not any([os.path.exists(path) for path in filenames]) and
            mozilla_aws_cli_config is None):
        raise click.BadParameter(
            'Config files {} not found'.format(" ".join(filenames)))

    for filename in filenames:
        try:
            # guard against empty files
            with open(filename, "r") as f:
                config = configparser.ConfigParser()

                if sys.version_info >= (3, 2):
                    config.read_file(f)
                else:
                    config.readfp(f)
        except FileNotFoundError:
            pass
        except (configparser.Error):
            raise click.BadParameter(
                'Config file {} is not a valid INI file.'.format(filename))
    if mozilla_aws_cli_config is not None:
        # Override the --config file contents with the mozilla_aws_cli_config
        # module contents
        config['DEFAULT'].update(mozilla_aws_cli_config.config)

    missing_settings = (
        {'client_id', 'idtoken_for_roles_url', 'well_known_url'} - set(config.defaults().keys()))

    if missing_settings:
        raise click.BadParameter(
            '{} setting{} are missing from the config files {}'.format(
                ', '.join(missing_settings),
                's' if len(missing_settings) > 1 else '',
                " ".join(filenames)))

    return config.defaults()


def validate_disable_caching(ctx, param, disabled):
    if disabled:
        disable_caching()


@click.command()
@click.option("-b", "--batch", is_flag=True, help="Run non-interactively")
@click.option(
    "-c",
    "--config",
    # TODO: Support Windows
    # TODO: Rename to something much better
    default=[
        os.path.join("/etc", "mozilla_aws_cli", "config"),
        os.path.join(DOT_DIR, "config"),
    ],
    help="Relative path to config file",
    metavar="<path>",
    callback=validate_config_file)
@click.option("-nc",
              "--no-cache",
              default=False,
              is_flag=True,
              help="Don't read locally cached files",
              callback=validate_disable_caching)
@click.option(
    "-o",
    "--output",
    default="envvar",
    type=click.Choice(["envvar", "shared", "awscli"]),
    help="How to output the AWS API keys",
    callback=validate_awscli_exists
)
@click.option(
    "-r",
    "--role-arn",
    help="AWS IAM Role ARN to assume",
    metavar="<arn>",
    callback=validate_arn)
@click.option("-v", "--verbose", is_flag=True, help="Print debugging messages")
@click.option("-w", "--web-console", is_flag=True, help="Open AWS web console")
def main(batch, config, no_cache, output, role_arn, verbose, web_console):
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
        batch=batch,
        client_id=config["client_id"],
        idtoken_for_roles_url=config["idtoken_for_roles_url"],
        jwks=config["jwks"],
        openid_configuration=config["openid-configuration"],
        output=output,
        role_arn=role_arn,
        scope=config.get("scope"),
        token_endpoint=config["openid-configuration"]["token_endpoint"],
        web_console=web_console,
        issuer_domain=config.get("issuer_domain", "aws.sso.mozilla.com")
    )

    login.login()


if __name__ == "__main__":
    main()
