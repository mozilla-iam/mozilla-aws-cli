#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

# https://github.com/mpdavis/python-jose/blob/master/CHANGELOG.md#330----2021-06-04
# https://github.com/sybrenstuvel/python-rsa/blob/main/CHANGELOG.md#version-43--45---released-2020-06-12
requirements = [
    "appdirs",
    "Click>=6.0",
    "flask>=1.0.2",
    "Werkzeug<2.1.0",
    "future",
    "requests>=2.20.1",
    "python-jose<3.3.0 ; python_version < '3.0'",
    "python-jose ; python_version >= '3.0'",
    "rsa==4.5 ; python_version < '3.0'",
    "rsa ; python_version >= '3.0'",
    "whichcraft==0.6.1"
]
# https://github.com/pytest-dev/pytest-runner/blob/main/CHANGES.rst#v530
setup_requirements = [
    "pytest-runner<5.3 ; python_version <'3.0'",
    "pytest-runner ; python_version >= '3.0'",
]
test_requirements = [
    "pytest",
    "pytest-cov",
    "python-jose",
    "requests-mock",
    'mock;python_version<"3.3"']
extras = {
    "test": test_requirements,
}

setup(
    name="mozilla_aws_cli",
    description="Command line tool to enable accessing AWS using federated single sign on",
    author="Mozilla Enterprise Information Security",
    author_email="iam@discourse.mozilla.org",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Natural Language :: English",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    entry_points={"console_scripts": ["maws=mozilla_aws_cli.cli:main"]},
    include_package_data=True,
    install_requires=requirements,
    long_description=readme,
    long_description_content_type='text/markdown',
    keywords="maws Mozilla AWS CLI",
    packages=find_packages(include=["mozilla_aws_cli"]),
    package_data={'mozilla_aws_cli': ['static/*', 'static/*/*']},
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    extras_require=extras,
    url="https://github.com/mozilla-iam/mozilla-aws-cli",
    version="1.2.5",
    zip_safe=False,
)
