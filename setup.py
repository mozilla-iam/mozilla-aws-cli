#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

requirements = [
    "appdirs",
    "Click>=6.0",
    "flask>=1.0.2",
    "future",
    "requests>=2.20.1",
    "python-jose",
]
setup_requirements = ["pytest-runner"]
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
        "Natural Language :: English",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
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
    version="1.2.0",
    zip_safe=False,
)
