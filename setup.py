#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

requirements = [
    "Click>=6.0",
    "python-jose==3.0.1",
    "flask==1.0.2",
    "requests==2.20.1",
    "PyYAML==5.1",
    "python-dateutil",
    "requests-cache==0.5.0",
    "pyxdg==0.26",
]
setup_requirements = ["pytest-runner"]
test_requirements = ["pytest", "pytest-cov"]
extras = {"test": test_requirements}

setup(
    author="Mozilla Infosec",
    author_email="infosec@mozilla.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
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
    description="CLI application that handled federated authentication for AWS users",
    entry_points={"console_scripts": ["federated_aws_cli=federated_aws_cli.cli:main"]},
    install_requires=requirements,
    long_description=readme,
    include_package_data=True,
    keywords="federated_aws_cli",
    name="federated_aws_cli",
    packages=find_packages(include=["federated_aws_cli"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    extras_require=extras,
    url="https://github.com/mozilla-iam/federated_aws_cli",
    version="0.0.1",
    zip_safe=False,
)
