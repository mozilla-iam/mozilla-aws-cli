# federated-boto


CLI application that handled federated authentication for AWS users

## Sequence diagram

[<img src="https://raw.githubusercontent.com/mozilla-iam/federated-boto/master/docs/img/sequence.png" width="100%">](docs/img/sequence.md)

## Prerequisites

* An OIDC provider like Auth0
* A well-known `openid-configuration` URL
* An Auth0 [application](https://auth0.com/docs/applications) created
  * Type : Native
  * Allowed Callback URLs : A list of the localhost URLs created from the 
    POSSIBLE_PORTS list of ports
  * The `client_id` for this application will be used in the CLI config file
* An AWS Identity provider
  * with an audience value of the Auth0 application client_id
  * with a [valid thumbprint](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html)

## Instructions

## Create a config

`cp config.yaml.inc config.yaml`

* `well_known_url`: The 
  [OpenID Connect Discovery Endpoint URL](https://openid.net/specs/openid-connect-discovery-1_0.html).
  ([Auth0](https://auth0.com/docs/protocols/oidc/openid-connect-discovery))
* client_id: The Auth0 `client_id` generated when the Auth0 
  [application](https://auth0.com/docs/applications) was created in the 
  prerequisites
* scope: A space delimited list of 
  [OpenID Connect Scopes](https://auth0.com/docs/scopes/current/oidc-scopes).
  For example `openid` and the scope where access control information is made
  available. Mozilla SSO would use `openid https://sso.mozilla.com/claim/groups`


## Run the tool

`python federated_boto/cli.py --role-arn arn:aws:iam::123456789012:role/example-role`

## Notes


```
# https://community.auth0.com/t/custom-claims-without-namespace/10999
# https://community.auth0.com/t/how-to-set-audience-for-aws-iam-identity-provider-configuration/12951
```
