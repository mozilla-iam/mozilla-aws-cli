# federated-boto


CLI application that handled federated authentication for AWS users

## Sequence diagram

![Sequence diagram](https://raw.githubusercontent.com/mozilla-iam/federated-boto/master/docs/img/sequence.png)

## Prerequisites

* An OIDC provider like Auth0
* A well-known `openid-configuration` URL
* An Auth0 [application](https://auth0.com/docs/applications) created
  * Type : Native
  * Allowed Callback URLs : A list of the localhost URLs created from the 
    POSSIBLE_PORTS list of ports
  * The `client_id` for this application will be used in the CLI config file
* An Auth0 [api](https://auth0.com/docs/apis)
  * Name : Recommended to use the same name as the Auth0 application created
    above for clarity
  * Signing Algorithm : `RS256`
  * Identifier : A URL of some kind that you'll use in the `audience` CLI config
    file setting.

## Instructions

`cp config.yaml.inc config.yaml`
`python federated_boto/cli.py`