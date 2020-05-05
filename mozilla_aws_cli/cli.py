from __future__ import absolute_import, print_function
from distutils.spawn import find_executable
import os
import logging

import click
import requests
import sys

from .cache import disable_caching
from .config import CONFIG_PATHS
from .login import Login

try:
    import mozilla_aws_cli_config
except ImportError:
    # There is no overriding configuration package that implements the
    # "mozilla_aws_cli_config" module. Use the normal config acquisition
    # methods
    mozilla_aws_cli_config = None

if sys.version_info[0] >= 3:
    import configparser
    basestring = str
else:
    FileNotFoundError = IOError
    import ConfigParser as configparser


logging.basicConfig(
    format="%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] "
           "%(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S")
logger = logging.getLogger()
logger.setLevel(logging.ERROR)
logging.getLogger("urllib3").propagate = False

VALID_OUTPUT_OPTIONS = ("awscli", "boto", "envvar", "js", "shared")


def validate_arn(ctx, param, value):
    del ctx, param  # we don't use these arguments
    # arn:aws:iam::account-id:role/role-name
    if value is None:
        return None
    elements = value.split(":")
    if (len(elements) != 6 or elements[0] != "arn" or elements[2] != "iam"
            or not elements[5].startswith("role/")):
        raise click.BadParameter("Role ARN {} is not a valid ARN".format(
            value))
    else:
        return value


def validate_output(ctx, param, value):
    del ctx, param  # we don't use these arguments
    if value is None:
        pass
    elif value.lower() == "awscli" and not find_executable("aws"):
        raise click.BadParameter("AWS CLI is not detected on local system.")

    return value


def validate_config_file(ctx, param, filenames):
    del ctx, param  # we don't use these arguments
    if isinstance(filenames, basestring):
        filenames = [filenames]

    if (not any([os.path.exists(path) for path in filenames]) and
            mozilla_aws_cli_config is None):
        raise click.BadParameter(
            "Config files {} not found".format(" ".join(filenames)))

    config = configparser.ConfigParser()
    for filename in filenames:
        try:
            # guard against empty files
            with open(filename, "r") as f:
                if sys.version_info >= (3, 2):
                    config.read_file(f)
                else:
                    config.readfp(f)
        except FileNotFoundError:
            pass
        except configparser.Error:
            raise click.BadParameter(
                "Config file {} is not a valid INI file.".format(filename))
    if not config.has_section("maws"):
        config.add_section("maws")

    result = dict(config.items("maws"))
    for boolean_field in ["print_role_arn"]:
        if boolean_field in result:
            result[boolean_field] = config.getboolean("maws", boolean_field)

    if mozilla_aws_cli_config is not None:
        # Override the --config file contents with the mozilla_aws_cli_config
        # module contents
        for key in mozilla_aws_cli_config.config:
            if key in result and result[key] != mozilla_aws_cli_config.config[key]:
                raise click.BadOptionUsage(
                    None,
                    "setting for `{}` exists in both the Python module ({}) "
                    "as well as one of the config files ({}). Either "
                    "uninstall the Python package or remove the setting from "
                    "the config file".format(
                        key, mozilla_aws_cli_config.__package__, filenames))

            result[key] = mozilla_aws_cli_config.config[key]
    missing_settings = (
        {"client_id",
         "idtoken_for_roles_url",
         "well_known_url"} - set(result.keys()))

    if missing_settings:
        missing_setting_list = ", ".join(
            ["`{}`".format(setting) for setting in missing_settings])
        plural = "s are" if len(missing_settings) > 1 else " is"
        filename_list = " ".join(filenames)
        message = (
            "{missing_setting_list} setting{plural} missing from config "
            "files: {filename_list}".format(
                missing_setting_list=missing_setting_list,
                plural=plural,
                filename_list=filename_list))
        raise click.BadOptionUsage(None, message)

    if result.get("output", "envvar") not in VALID_OUTPUT_OPTIONS:
        raise click.BadParameter("{}".format(result["output"]),
                                 param_hint="`output` in config file")
    return result


def validate_cache(ctx, param, cache):
    del ctx, param  # we don't use these arguments
    if not cache:
        disable_caching()
    return cache


@click.command()
@click.option("-b", "--batch", is_flag=True, help="Run non-interactively")
@click.option(
    "-c",
    "--config",
    # TODO: Support Windows
    # TODO: Rename to something much better
    default=CONFIG_PATHS,
    help="Relative path to config file",
    metavar="<path>",
    callback=validate_config_file)
@click.option("--cache/--no-cache",
              " /-nc",
              default=True,
              help="Use locally cached files",
              callback=validate_cache)
@click.option(
    "-o",
    "--output",
    type=click.Choice(VALID_OUTPUT_OPTIONS),
    help="How to output the AWS API keys",
    callback=validate_output
)
@click.option("--print-url", is_flag=True, help="Print the federation URL to stdout")
@click.option("--profile",
              metavar="<profile>",
              help="Override profile name used with `awscli` or `shared` "
                   "output")
@click.option(
    "-r",
    "--role-arn",
    help="AWS IAM Role ARN to assume",
    metavar="<arn>",
    callback=validate_arn)
@click.option("-v", "--verbose", is_flag=True, help="Print debugging messages")
@click.option("-w", "--web-console", is_flag=True, help="Open AWS web console")
def main(batch, config, cache, output, print_url,
         profile, role_arn, verbose, web_console):
    """Fetch AWS API Keys using SSO web login"""
    if verbose:
        logger.setLevel(logging.DEBUG)

    # Order of precedence : output, config["output"], "envvar"
    profile = config.get("profile") if profile is None else profile
    config["output"] = output if output is not None else config.get(
        "output", "envvar")
    try:
        config["openid-configuration"] = requests.get(
            config["well_known_url"]).json()
        config["jwks"] = requests.get(
            config["openid-configuration"]["jwks_uri"]).json()
    except requests.exceptions.ConnectionError as e:
        print("Unable to contact identity provider {} : {}".format(
            config["well_known_url"], e), file=sys.stderr)
        return False
    if batch and role_arn is None:
        raise click.exceptions.UsageError(
            "You must pass a role_arn in batch mode")
    if web_console and print_url:
        raise click.exceptions.UsageError(
            "Cannot print URL to output and redirect to web console")

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
        config=config,
        profile_name=profile,
        role_arn=role_arn,
        scope=config.get("scope"),
        token_endpoint=config["openid-configuration"]["token_endpoint"],
        web_console=web_console,
        issuer_domain=config.get("issuer_domain", "aws.sso.mozilla.com"),
        cache=cache,
        print_url=print_url
    )

    login.login()


if __name__ == "__main__":
    main()
