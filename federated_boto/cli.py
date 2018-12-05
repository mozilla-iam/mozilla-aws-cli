# -*- coding: utf-8 -*-

import click
from config import parse_config


@click.command()
@click.option('--config_file', default='config.yaml', help='Relative path to config file')
@click.option('--role_arn', required=True, help='RoleARN to assume')
def main(config_file, role_arn):
    # Parse config file
    config = parse_config(config_file)
    click.echo("Obtaining temporary credentials for {0}".format(role_arn))
    return 0


if __name__ == "__main__":
    main()
