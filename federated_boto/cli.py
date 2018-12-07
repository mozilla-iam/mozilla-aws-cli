# -*- coding: utf-8 -*-

import click
import requests
import logging
import platform
from jose import jwt  # This is optional so we can probably remove it and the code that uses it
from config import parse_config
from login import login
import sts_conn

ENV_VARIABLE_NAME_MAP = {
    'AccessKeyId': 'AWS_ACCESS_KEY_ID',
    'SecretAccessKey': 'AWS_SECRET_ACCESS_KEY',
    'SessionToken': 'AWS_SESSION_TOKEN'
}

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_aws_env_variables(credentials):
    result = ''
    verb = 'set' if platform.system() == 'Windows' else 'export'

    for key in [x for x in credentials if x in ENV_VARIABLE_NAME_MAP]:
        result += '{} {}={}\n'.format(
            verb,
            ENV_VARIABLE_NAME_MAP[key],
            credentials[key]
        )
    return result


@click.command()
@click.option(
    '-c', '--config-file', default='config.yaml',
    help='Relative path to config file')
@click.option('-r', '--role-arn', required=True, help='RoleARN to assume')
@click.option(
    '-o', '--output', default='envvar', type=click.Choice(['envvar', 'sha1']),
    help='How to output the AWS API keys')
@click.option('-v', '--verbose', is_flag=True, help="Print debugging messages")
def main(config_file, role_arn, output, verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)

    # Parse config file
    config = parse_config(config_file)
    config['openid-configuration'] = requests.get(
        config['well_known_url']).json()
    config['jwks'] = requests.get(
        config['openid-configuration']['jwks_uri']).json()
    logger.debug('JWKS : {}'.format(config['jwks']))

    logger.debug('Config : {}'.format(config))

    bearer_token = login(
        config['openid-configuration']['authorization_endpoint'],
        config['openid-configuration']['token_endpoint'],
        config['client_id'],
        config['audience'])

    logger.debug('Bearer token : {}'.format(bearer_token))

    bearer_dict = jwt.decode(
        token=bearer_token,
        key=config['jwks'],
        audience=config['audience']
    )
    logger.debug('Bearer dict : {}'.format(bearer_dict))

    credentials = sts_conn.get_credentials(
        bearer_token,
        role_arn=role_arn
    )

    logger.debug(credentials)

    if output == 'envvar':
        print(get_aws_env_variables(credentials))


if __name__ == "__main__":
    main()
