#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `federated_aws_cli` package."""

import os
import sys
from click.testing import CliRunner
from federated_aws_cli import cli
from federated_aws_cli.role_picker import show_role_picker
if sys.version_info >= (3, 3):
    from unittest.mock import patch
else:
    from mock import patch


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0
    assert 'Show this message and exit.' in help_result.output


def test_parse_config():
    good_arn = 'arn:aws:iam::123456789012:role/MyRole'
    bad_arn = 'bogus'
    good_config_content = '''well_known_url: http://auth.example.com/.well-known/openid-configuration
client_id: abcdefghijklmnopqrstuvwxyz012345
scope: openid'''
    cases = {
        'malformed yaml': {
            'filename': os.path.expanduser(os.path.join("~", ".malformed_yaml")),
            'content': '- a z=x:\ny: "${z}"',
            'args': ['-c', os.path.expanduser(os.path.join("~", ".malformed_yaml")), '-r', good_arn]
        },
        'missing config setting': {
            'filename': os.path.expanduser(os.path.join("~", ".missing_config_setting")),
            'content': 'well_known_url: http://auth.example.com/.well-known/openid-configuration\n',
            'args': ['-c', os.path.expanduser(os.path.join("~", ".missing_config_setting")), '-r', good_arn]
        },
        'bad role arn': {
            'filename': os.path.expanduser(os.path.join("~", ".good_config")),
            'content': good_config_content,
            'args': ['-c', os.path.expanduser(os.path.join("~", ".good_config")), '-r', bad_arn]
        }
    }

    runner = CliRunner()
    with runner.isolated_filesystem():
        results = {}
        for case in cases:
            with open(cases[case]['filename'], 'w') as f:
                f.write(cases[case]['content'])
            results[case] = runner.invoke(cli.main, cases[case]['args'])

        assert results['malformed yaml'].exit_code != 0
        assert 'is not valid YAML' in results['malformed yaml'].output

        assert results['missing config setting'].exit_code != 0
        assert 'settings are missing from the config file' in results['missing config setting'].output

        assert results['bad role arn'].exit_code != 0
        assert 'is not a valid ARN' in results['bad role arn'].output


@patch('federated_aws_cli.role_picker.show_menu')
def test_show_role_picker(show_menu):
    roles_and_aliases = {
        'roles': [
            'arn:aws:iam::123456789012:role/role-mariana',
            'arn:aws:iam::123456789012:role/role-tonga',
            'arn:aws:iam::123456789012:role/a/path/role-philippine',
            'arn:aws:iam::234567890123:role/path/to/foraker',
            'arn:aws:iam::234567890123:role/different/path/to/blackburn',
        ],
        'aliases': {
            '123456789012': ['Trenches-Account'],
            '234567890123': ['Mountains-Account'],
        }
    }
    show_role_picker(roles_and_aliases)
    show_menu.assert_called_with(
        ['Mountains-Account (234567890123) : blackburn',
         'Mountains-Account (234567890123) : foraker',
         'Trenches-Account (123456789012) : role-mariana',
         'Trenches-Account (123456789012) : role-philippine',
         'Trenches-Account (123456789012) : role-tonga'],
        ['arn:aws:iam::234567890123:role/different/path/to/blackburn',
         'arn:aws:iam::234567890123:role/path/to/foraker',
         'arn:aws:iam::123456789012:role/role-mariana',
         'arn:aws:iam::123456789012:role/a/path/role-philippine',
         'arn:aws:iam::123456789012:role/role-tonga']
    )
