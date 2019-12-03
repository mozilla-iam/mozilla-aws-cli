#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `mozilla_aws_cli` package."""

import uuid

from click.testing import CliRunner
from mozilla_aws_cli import cli


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ["--help"])
    assert help_result.exit_code == 0
    assert "Show this message and exit." in help_result.output


def test_parse_config():
    good_config_content = """[DEFAULT]
well_known_url = http://auth.example.com/.well-known/openid-configuration
client_id = abcdefghijklmnopqrstuvwxyz012345
idtoken_for_roles_url = https://example.com/roles"""

    bad_arn = "bogus"
    bad_output_setting = good_config_content + "\noutput = blahblahblah"
    good_arn = "arn:aws:iam::123456789012:role/MyRole"
    missing_config_setting = """[DEFAULT]
well_known_url = http://auth.example.com/.well-known/openid-configuration
    """

    cases = {
        "malformed ini": {
            "content": "- a z=x:\ny: \"${z}\"",
            "args": ["-r", good_arn]
        },
        "missing config setting": {
            "content": missing_config_setting,
            "args": ["-r", good_arn]
        },
        "bad role arn": {
            "content": good_config_content,
            "args": ["-r", bad_arn]
        },
        "bad output setting": {
            "content": bad_output_setting,
            "args": ["-r", good_arn]
        },
    }

    runner = CliRunner()
    with runner.isolated_filesystem():
        results = {}
        for case in cases:
            args = cases[case]["args"]

            # Use a random filename, if "-c" isn"t specified in the arguments above
            filename = str(uuid.uuid4())
            if "-c" not in args:
                args += ["-c", filename]

            with open(filename, "w") as f:
                f.write(cases[case]["content"])

            results[case] = runner.invoke(cli.main, args)

        assert results["malformed ini"].exit_code != 0
        assert "is not a valid INI" in results["malformed ini"].output

        assert results["missing config setting"].exit_code != 0
        assert "settings are missing from config files" in results["missing config setting"].output

        assert results["bad role arn"].exit_code != 0
        assert "is not a valid ARN" in results["bad role arn"].output

        assert results["bad output setting"].exit_code != 0
        assert "`output` in config file" in results["bad output setting"].output
