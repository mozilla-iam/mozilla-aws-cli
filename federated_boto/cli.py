# -*- coding: utf-8 -*-

import click
from config import parse_config
import requests


def retrieve_well_known(well_known_url):
    resp = requests.get(well_known_url)
    data = resp.json()
    return data['token_endpoint'], data['authorization_endpoint']


@click.command()
@click.option('--config_file', default='config.yaml', help='Relative path to config file')
@click.option('--role_arn', required=True, help='RoleARN to assume')
def main(config_file, role_arn):
    # Parse config file
    config = parse_config(config_file)
    config['token_endpoint'], config['authorization_endpoint'] = retrieve_well_known(config['well_known_url'])

    print(config)
    click.echo("Obtaining temporary credentials for {0}".format(role_arn))
    return 0


if __name__ == "__main__":
    main()
