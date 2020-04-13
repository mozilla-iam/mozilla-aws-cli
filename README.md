# mozilla-aws-cli

Command line tool to enable accessing AWS using federated single sign on

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

Users can either configure Mozilla AWS CLI with a [python package](#creating-enterprise--organization-configuration)
provided by their organization, or they can create a config file by hand.

## Create a config file

The default files that configuration is fetched from are
* Windows
  * `C:\Users\<user>\AppData\Roaming\Mozilla AWS CLI\config.ini`
  * `C:\ProgramData\Mozilla AWS CLI\config.ini`
* Mac
  * `/Users/<user>/.config/maws/config.ini`
  * `/etc/maws/config.ini`
* Linux
  * `/etc/xdg/xdg-ubuntu/maws/config.ini` (for Ubuntu)
  * `/home/<user>/.config/maws/config.ini`

where settings in `/etc` or `C:\ProgramData` are overridden by settings in 
`C:\Users\<user>\AppData\Roaming\` or `~/.config/maws/` or `/Users/`.

Users can also assert which config file(s) to read from using the `-c` or `--config`
command line arguments.

These config files use the standard [INI file format](https://en.wikipedia.org/wiki/INI_file).

The `config` file should contain a single section called `[maws]` and can
contain the following settings.

There are three *required* settings which must either be set in a [python package](#creating-enterprise--organization-configuration)
provided by the organization or in the user's config file. Those required
settings are

* `well_known_url`: The
  [OpenID Connect Discovery Endpoint URL](https://openid.net/specs/openid-connect-discovery-1_0.html).
  ([Auth0](https://auth0.com/docs/protocols/oidc/openid-connect-discovery))
* `client_id`: The Auth0 `client_id` generated when the Auth0
  [application](https://auth0.com/docs/applications) was created in the
  prerequisites
* `idtoken_for_roles_url` : The URL of the ID Token For Roles API. This URL
  comes from the location that the user's organization has deployed the
  [idtoken_for_roles](https://github.com/mozilla-iam/mozilla-aws-cli/tree/master/cloudformation)
  API. This API lets a user exchange an ID token for a list of groups and roles
  that they have rights to. This URL should be the base URL of the API, ending
  in `/`

Additional optional settings that can be configured in the config file are
 
* `scope`: A space delimited list of
  [OpenID Connect Scopes](https://auth0.com/docs/scopes/current/oidc-scopes).
  For example `openid`. Avoid including a scope which passes too much data which
  will exceed the maximum AWS allowed size of the ID Token (for example at
  Mozilla we neglect to include the raw full group list which is included in the
  ID Token when the `https://sso.mozilla.com/claim/groups` scope is requested.
* `output` : The output format for the tool to use. This must be one of the
  following values
  * `awscli` : `maws` calls into the `aws` application, configuring it directly
  * `boto` : Outputs JSON to stdout to be directly consumed by the
    [boto3](https://github.com/boto/boto3) library
  * `envvar` : A set of environment variables that load the temporary
    credentials directly in to the environment without writing them to a file
  * `js` : Outputs JSON to stdout to be directly consumed by the
    [AWS JavaScript SDK](https://github.com/aws/aws-sdk-js)
  * `shared` : A set of environment variables that reference a dedicated maws
    AWS config file which is created

* `print_role_arn` : Whether or not `maws` should display the AWS IAM Role ARN
  on the command line. This can values like `yes`, `no`, `true`, `false`

The resulting config would looks something like this
```ini
[maws]
client_id = abcdefg
idtoken_for_roles_url = https://roles-and-aliases.example/roles
well_known_url = http://auth.example.com/.well-known/openid-configuration
```

## Run the tool

There are various ways you can run `maws`. The tool can output environment
variable setting text to activate your AWS session inside your terminal. Here
are some methods to use the tool.

### Subcommand

You could run `maws` within a `$()` sub-shell and execute the results

* Interactively prompt for which IAM role to assume
  * `$(maws)`
* Pass the IAM role to assume as a command line argument
  * `$(maws --role-arn arn:aws:iam::123456789012:role/example-role)`
* Not only enable command line access to AWS, also log into the web console
  * `$(maws -w)`

> :warning: **Users of [YADR](https://github.com/skwp/dotfiles) and zsh**:
> Subcommands can result in a broken authentication flow, and so it is
> recommended that you use either process substitution or `eval`, as described
> below.

### Process substitution

This uses [process substitution](http://tldp.org/LDP/abs/html/process-sub.html).
Here are some examples of how you could run it

`source <(maws -w)`

### Eval

You could eval the results

`eval $(maws --role-arn arn:aws:iam::123456789012:role/example-role)`

### Copy paste

Take the output of the command and copy paste it into your terminal

`maws`

### Using programmatically

In general, it is recommended to keep your code independent of `maws` by
using environmental variables such as `AWS_PROFILE` and letting the
underlying libraries read from your local AWS configuration. However,
there are situations (such as needing to connect to multiple accounts)
where this may not be an option.

In these cases, `maws` can be used directly with libraries such as
[boto3](https://github.com/boto/boto3). To do this, capture the output
from  `maws` and use it directly in your program:

```python
import boto3
import json
from subprocess import Popen, PIPE

if __name__ == "__main__":
    with Popen(["maws", "-o", "boto"], stdout=PIPE) as proc:
        boto_args = json.loads(proc.stdout.read())

    s3_client = boto3.client('s3', **boto_args)

    print(s3_client.list_buckets())
```

```javascript
const AWS = require("aws-sdk");
const child_process = require("child_process");

const botoArgs = JSON.parse(child_process.spawnSync("maws", ["-o", "js"]).stdout);

new AWS.S3(botoArgs).listBuckets({}, (err, data) => {
  console.log(data);
});
```

## Sequence diagram

[<img src="https://raw.githubusercontent.com/mozilla-iam/mozilla-aws-cli/master/docs/img/sequence.png" width="100%">](docs/img/sequence.md)

## Notes


```
# https://community.auth0.com/t/custom-claims-without-namespace/10999
# https://community.auth0.com/t/how-to-set-audience-for-aws-iam-identity-provider-configuration/12951
```

## Details

This is a collection of technical details that we've decided or discovered in
building the mozilla-aws-cli

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
  a new list containing a single element `["mfa"]`. We've 
  [opened a bug with Auth0](https://support.auth0.com/tickets/00427989) in hopes
  that they will change to *appending* to the `amr` assertion.
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

### Supported IAM Policy Features

The Auth0 rule which finds the intersection in the groups a user is a member of
with the union of all groups used in all AWS accounts IAM policies won't
support [all IAM policy operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String).
Here are the various use cases and whether they are supported or not


#### Supported
An AWS account holder wants to

* enable users that are members of group "foo" to assume role 
  arn:aws:iam::123456789012:role/baz
  * supported
  * `StringLike`, `StringEquals`
* enable users that are members of group "foo" as well as users that are members
  of group "bar" to assume role arn:aws:iam::123456789012:role/baz
  * supported
  * `StringLike`, `StringEquals` for a list of values
* enable users that are members of any group like "fo*" to assume role
  arn:aws:iam::123456789012:role/baz
  * supported
  * `StringLike` with wildcards

#### Not Supported
An AWS account holder wants to

* enable users that are members of both group "foo" and group "bar" to assume
  role arn:aws:iam::123456789012:role/baz
  * not supported
  * multiple `StringLike` or `StringEquals` conditions
* enable users that are members of group "foo" but not allow users that are
  members of group "FOO" to assume role arn:aws:iam::123456789012:role/baz
  * not supported
  * when assembling the group list to pass to AWS, we will do case insensitive
    matching. Additionally, there shouldn't ever be a case where two groups
    exist with the same characters in their name but different cases
  * multiple `StringEquals` conditions where the values differ only in case
* enable users that are not members of group "bar" to assume role
  arn:aws:iam::123456789012:role/baz
  * not supported
  * `StringNotEquals`, `StringNotLike`
* enable users that are members of group "foo" but not members of group "bar"
  to assume role arn:aws:iam::123456789012:role/baz
  * not supported
  * multiple conditions including `StringNotEquals`, `StringNotLike`

## Troubleshooting

If you don't see a role listed in the role picker which you would expect to have
access to, possible reasons are :

* The IAM role was recently modified and
  1. the hourly scanner hasn't yet run to update the list of available roles.
  2. the list of available roles is current but the API that sits in front of
     it is using an out of date cached copy
  3. the list of available roles is current but the Auth0 rule is using an out
     of date cached copy of the available roles and as a result, isn't passing
     an "amr" claim with your current complete list of groups
  * If the cause is 1 or 2 you can still assume that role, just not using this
    menu. Instead pass the role ARN on the command line.
* The conditions in the role don't allow you to access it because
  * The role has a different "Principal" "Federated" value than it should
    * Dev
      * Federated : `arn:aws:iam::*:oidc-provider/auth.mozilla.auth0.com/`
      * Aud : `N7lULzWtfVUDGymwDs0yDEq6ZcwmFazj`
    * Prod
      * Federated : `arn:aws:iam::*:oidc-provider/auth-dev.mozilla.auth0.com/`
      * Aud : `xRFzU2bj7Lrbo3875aXwyxIArdkq1AOT`
  * The role has the wrong "Action" value which should be
    * `sts:AssumeRoleWithWebIdentity`
  * The role has an "aud" condition that doesn't match the Auth0 client ID
    being passed in the "aud" claim from Auth0
    * Dev : `xRFzU2bj7Lrbo3875aXwyxIArdkq1AOT`
    * Prod : `N7lULzWtfVUDGymwDs0yDEq6ZcwmFazj`
  * The key name of the "aud" condition is incorrect
    * Dev : `auth-dev.mozilla.auth0.com/:aud`
    * Prod : `auth.mozilla.auth0.com/:aud`
  * The key name of the "amr" condition is incorrect
    * Dev : `auth-dev.mozilla.auth0.com/:amr`
    * Prod : `auth.mozilla.auth0.com/:amr`
  * You aren't a member of any of the groups listed in "amr" conditions
* Your AWS account does not delegate security auditing rights to the Enterprise
  Information Security team so the group role map builder can't scan the IAM
  roles in your AWS account
* There is a bug
  * in the Auth0 rule that filters the list of groups that you are a member of
    such that the "amr" claim returned to you is missing a group that you need
    to meet an IAM Role condition
  * in the group role map builder that produces the map of groups to roles to
    enable the Auth0 rule and the role picker menu to know which roles are
    available to you
  * in the ID token for role API that allows you to exchange your ID token for
    a list of roles so that the role picker can show you a menu of available
    roles

## Development

When developing the tool and testing you can run it without installing it like
this

`python -m mozilla_aws_cli.cli --role-arn arn:aws:iam::123456789012:role/example-role`

Note : You must run `python -m mozilla_aws_cli.cli` instead of
`python mozilla_aws_cli/cli.py` because mozilla_aws_cli uses absolute imports.

## Creating enterprise / organization configuration

If you want to deploy the Mozilla AWS CLI across your organization and establish
default configuration values without requiring users to create config files you
can do so by implementing a standard `mozilla_aws_cli_config` module.

Here are the steps assuming an example organization called Yoyodyne

1. Create a new code repo. A good name would be `mozilla-aws-cli-yoyodyne`
2. In that repo create a `setup.py`
   ```python
   #!/usr/bin/env python

   from setuptools import setup

   setup(
       name="mozilla-aws-cli-yoyodyne",
       description="Yoyodyne specific deployment of the mozilla_aws_cli",
       install_requires=["mozilla_aws_cli"],
       packages=["mozilla_aws_cli_config"],
       url="https://github.com/yoyodyne/mozilla-aws-cli-yoyodyne",
       version="1.0.0",
   )
   ```
   * `install_requires` depends on the `mozilla_aws_cli` to ensure that if you
     instruct the user to `pip install mozilla-aws-cli-yoyodyne` they will get
     the Yoyodyne config and the tool
3. Create a directory called `mozilla_aws_cli_config`
   * This is the reserved / well known module name that every organization can
     implement. This name must be `mozilla_aws_cli_config` exactly and not
     include any part of your organization name (e.g. Yoyodyne)
4. Within that `mozilla_aws_cli_config` directory create a single `__init__.py`
   file. This will contain your organizations default configuration settings
5. In this `__init__.py` file create a single variable called `config`
   containing your organizations default configuration settings.
   * Yoyodyne's `__init__.py` might look like
     ```python
     config = {
         "client_id": "abcdefghiJKLMNOPQRSTUVWXYZ012345",
         "idtoken_for_roles_url": "https://roles-and-aliases.sso.yoyodyne.com/roles",
         "well_known_url": "https://auth.yoyodyne.auth0.com/.well-known/openid-configuration"
     }
     ```

The resulting repository called `mozilla-aws-cli-yoyodyne` would look like this

```
mozilla-aws-cli-yoyodyne/
├── mozilla_aws_cli_config
│   └── __init__.py
└── setup.py
```

## Other projects in this space

* https://github.com/aidan-/aws-cli-federator
* https://github.com/Nike-Inc/gimme-aws-creds
* https://github.com/sportradar/aws-azure-login
* https://github.com/oktadeveloper/okta-aws-cli-assume-role
* https://github.com/jmhale/okta-awscli
* https://github.com/prolane/samltoawsstskeys
* https://github.com/physera/onelogin-aws-cli
* https://github.com/kxseven/axe/blob/master/bin/subcommands/axe-token-krb5formauth-create
* https://github.com/openstandia/aws-cli-oidc