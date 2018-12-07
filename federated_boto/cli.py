# -*- coding: utf-8 -*-

import click
import requests
import logging
from jose import jwt
from config import parse_config
from login import login
import sts_conn


logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@click.command()
@click.option('--config_file', default='config.yaml',
              help='Relative path to config file')
@click.option('--role_arn', required=True, help='RoleARN to assume')
def main(config_file, role_arn):
    # Parse config file
    config = parse_config(config_file)
    config['openid-configuration'] = requests.get(
        config['well_known_url']).json()
    config['jwks'] = requests.get(
        config['openid-configuration']['jwks_uri']).json()
    logger.debug('JWKS : {}'.format(config['jwks']))

    logger.debug('Config : {}'.format(config))
    click.echo("Obtaining temporary credentials for {0}".format(role_arn))

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
    return 0


if __name__ == "__main__":
    main()
