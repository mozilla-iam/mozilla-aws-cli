# -*- coding: utf-8 -*-

"""Console script for federated_boto."""
import os
import sys

import click

import login


@click.command()
def main(args=None):
    """Console script for federated_boto."""
    click.echo("Replace this message by putting your code into "
               "federated_boto.cli.main")
    click.echo("See click documentation at http://click.pocoo.org/")
    return 0


if __name__ == "__main__":
    #sys.exit(main())  # pragma: no cover

    client_id = 'client_id'
    tenant = 'tenant'
    audience = 'audience'
    login.login(client_id, tenant, audience)
