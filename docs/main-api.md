# Main CLI Function API

This document describes the interface that must be satifised by the
main function invoked by the CLI given input parameters provided by
the user.

## Terminology

**ACE**

> Authorization Code Exchanger - A service responsible for communicating
> with Auth0.

## Parameters

An implementation of the main function for the CLI tool must accept the
following parameters, in the order listed here.

| Name | Type | Description | Example |
| ---- | ---- | ----------- | ------- |
| profile | string | The name of the AWS profile to assume | my-profile |
| ace-address | string | The base address of the ACE server | https://ace.mozilla.com |

## Results

An implementation of the main function for the CLI tool must return a
dictionary containing the following fields.

**Note** that all of the keys are strings, given by the `name` column. The
type of the corresponding value is given by the `type` column.

| Name | Type | Description | Example |
| ---- | ---- | ----------- | ------- |
| token | string | The security token returned by AWS | abcdef... |

## Example

```py
profile = "retrieved from command-line arguments"
ace_address = "retrieved from command-line arguments"

results = authenticate(profile, ace_address)
token = results['token']
```
