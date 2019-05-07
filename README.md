# federated-aws-cli


CLI application that handled federated authentication for AWS users

## Sequence diagram

[<img src="https://raw.githubusercontent.com/mozilla-iam/federated-aws-cli/master/docs/img/sequence.png" width="100%">](docs/img/sequence.md)

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

`python federated_aws_cli/cli.py --role-arn arn:aws:iam::123456789012:role/example-role`

## Notes


```
# https://community.auth0.com/t/custom-claims-without-namespace/10999
# https://community.auth0.com/t/how-to-set-audience-for-aws-iam-identity-provider-configuration/12951
```

## Details

This is a collection of technical details that we've decided or discovered in
building the federated-aws-cli

* The user group list should be set in the OIDC claim as a list of groups
  instead of a string with delimiters
  * The `amr` claim allows for passing a list
  * By using a list we don't need to worry about choosing a delimiter and
    ensuring the delimiter is not allowed in the group name
  * The [`ForAnyValue:StringLike`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String)
    IAM policy condition operator doesn't need `*` wildcard characters in the
    value since each group listed in the policy is a full group name which will
    match a full group name in the list passed in `amr`
* Even if you only wish to allow a single user group to assume a role, you still
  must use the [`ForAnyValue:StringLike`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_multi-value-conditions.html)
  operator, not the `StringLike` operator. It's not clear why this is the case.
* AWS has a maximum size that either the `id_token` or the `amr` assertion can
  be.
  * When this maximum size is exceeded AWS returns the error 
    `PackedPolicyTooLarge Serialized token too large for session`
  * It's possible that the size limit is not able to be determined because
    AWS performs a packing or compression step on it's size such that the size
    of the `amr` assertion doesn't have a linear relationship with the size
    of the object AWS tests against it's limit
  * For example a `amr` value that is a list of 30 group names with an 
    `id_token` length of 800 characters triggers this error.
* Currently, when a user logs into Auth0 for the first time and performs a Duo
  MFA authentication, Auth0 overwrites the `amr` assertion that we create with
  a new list containing a single element `["mfa"]`. We've opened a bug with
  Auth0 in hopes that they will change to *appending* to the `amr` assertion.
  * If they make this change, the `amr` assertion would, in that case, contain
    the list of groups *and* what would appear like a group called `mfa`. We
    would need to do some checks to ensure that nobody starts using a real group
    called `mfa`
* The `amr` assertion in the OIDC spec isn't supposed to be used to pass a list
  of groups. It's also not supposed to be used to pass a string like 
  `authenticated` like AWS does with cognito.
  * The [purpose of the `amr` assertion](https://tools.ietf.org/html/rfc8176#section-1)
    is to provide an RP with a list of 
    > identifiers for authentication methods used in the authentication
  * [RFC8176](https://tools.ietf.org/html/rfc8176#page-4) states
    > The "amr" values defined by this specification are not intended to be
    > an exhaustive set covering all use cases.  Additional values can and
    > will be added to the registry by other specifications.
  * The RFC then goes on to define a [list of allowed values](https://tools.ietf.org/html/rfc8176#section-2)
    which make it clear that `authenticated` or group names are not correct
  * Given this, it's possible that down the road
    * AWS will begin to use a different assertion than `amr` to conform to the
      spec
    * Auth0 will disallow setting non conforming values in `amr`
  * If this happens we would need to change how we do things
* By having an Auth0 rule that queries some external resource (such as the
  group to role mapping file) and added delay to login is introduced and a risk
  of a problem in fetching the mapping file which could cause login to fail
* We use the `amr` assertion because it appears to be the only way to pass data
  to AWS
  * The [documentation](https://docs.aws.amazon.com/it_it/IAM/latest/UserGuide/list_awssecuritytokenservice.html#awssecuritytokenservice-web-identity-provider_oaud)
    indicates that there are 3 assertions that can be used in IAM policy
    conditions, `aud` `oaud` and `sub`
  * In testing we've found that
    `aud` is passed and we use it for the Auth0 client ID
    `sub` is passed and we use it for the Auth0 username
    `oaud` is not passed
    `amr` is passed
* By passing a group list in the `amr` assertion we take on the following risks
  * At some point some user may try to login to AWS with SSO and login will fail
    due to the `PackedPolicyTooLarge` error. This will occur when
    * Enough AWS account holders across our many AWs accounts create IAM 
      policies which allow a diverse set of user groups to access various roles
    * This unlucky user has access to so many different AWS accounts and roles
      because they work across many teams that the union of all the AWS groups
      which grant them access to the various roles exceeds the
      `PackedPolicyTooLarge` limit
  * We can't be sure at the point that we send the assertion that it will fail
    because we can't know the hard limit on the size of the `amr` assertion or
    the `id_token` in total
* We plan to try to log and track users experience over time to see if the
  group list size issue is becoming a problem. To do so we'll want to see
  * The size of the `amr` assertion being passed each time a user logs in
  * If AWS ever returns a `PackedPolicyTooLarge` error
