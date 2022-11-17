# Supporting Services

This directory contains deployment tools, AWS Lambda code and CloudFormation 
templates for the two services that Mozilla AWS CLI depend on :

* Group Role Map Builder
* ID Token For Roles API

## Group Role Map Builder

The Group Role Map Builder is an AWS Lambda function that [runs every 10 minutes](https://github.com/mozilla-iam/mozilla-aws-cli/blob/6de1d9223f14d2ad5cae85856e2c7036ab8237eb/cloudformation/group_role_map_builder/group_role_map_builder.yaml#L154)
or on [demand](https://github.com/mozilla-iam/federated-aws-rp/blob/4ae6ae2c2b2b11a10e337c5c803e52a7b5c7653e/functions/federated_aws_rp/app.py#L125). 
The builder iterates over all AWS accounts, reads all the IAM Roles in those 
accounts and collects together all of the IAM Roles which use the AWS Federated 
login method.

The builder scans these federated roles and extracts the user groups (LDAP 
groups or people.mozilla.org mozilliansorg groups) that exist in the trust 
policies of those roles.

The builder then produces a map of the relationship between the roles and the groups.

This map is needed for a few reasons

-   To be able to present a user with a "role picker" UI which lists all IAM 
    Roles in all AWS accounts that they're permitted to use based on their group 
    membership so they can pick one
-   To filter a user's group list (the list of groups that they are a member of) 
    to only the groups which could have an effect on their permission to assume 
    an IAM Role. Most user's groups won't relate to AWS IAM Roles and can be 
    filtered out before being sent to AWS

The builder must be run in an AWS account that has permission to assume a role 
in all of the AWS accounts in order to read their IAM policies. Those IAM Roles 
which the builder will assume in foreign AWS accounts, must have rights to

-   `iam:ListRoles`
-   `iam:ListAccountAliases`

The builder must also be able to [discover the AWS IAM Roles](https://github.com/mozilla-iam/mozilla-aws-cli/blob/6de1d9223f14d2ad5cae85856e2c7036ab8237eb/cloudformation/group_role_map_builder/functions/group_role_map_builder.py#L519-L545) 
that it should assume in every AWS account by querying the [CloudFormation Cross Account Output](https://github.com/mozilla/cloudformation-cross-account-outputs) 
system. At Mozilla this system is used to record the IAM Roles that people 
create in their AWS accounts.

The reason why the Group Role Map Builder is needed is a bit complicated (more 
information in [these details](https://github.com/mozilla-iam/mozilla-aws-cli#details)). 
AWS has a maximum permitted size for the list of 
groups that a user is a member of when it's sent over during a sign in. That 
maximum length is somewhere under 800 characters. At Mozilla, it's not unusual 
for a user to be a member of enough groups such that this maximum size is exceeded. 
As a result, we need to use the Group Role Map Builder to filter out all of a 
user's groups which have no impact on the user's permissions in AWS IAM Roles.

### AWS Account ID to Alias Map

While the builder collects the information to produce the Group Role Map, it
also fetches the AWS Account alias for each account. With this, it produces an
AWS Account ID to Alias map which is made available by the ID Token For Roles
API and which is used to display account aliases in the IAM Role Picker UI.

The map could also be used by other systems looking to either enumerate Mozilla
AWS Accounts or convert an AWS Account ID to an Alias.

This Account ID Alias map also includes manually defined entries of Account ID
to Alias mappings. These manually defined entries are intended to capture the
names of AWS Accounts that don't use SSO. Though not needed by the IAM Role
Picker (since the accounts don't use SSO), it does make the alias map more
complete fore use by other tools.

These manually defined entries are stored in the S3 file defined in the
`ManualAccountAliasesS3FilePath` CloudFormation stack parameter, which by
default is set to `manual-account-aliases.json` and stored in the [S3 Bucket](https://github.com/mozilla-iam/mozilla-aws-cli/blob/a6e8152dbc9efb2ed785e4b9bdb208ec09cb4cc0/cloudformation/Makefile#L10)

More Mozilla specific information on the Group Role Map Builder and AWS Account
ID to Alias map can be found in [internal documentation](https://mana.mozilla.org/wiki/display/SECURITY/AWS+Federated+Login+with+Single+Sign+On)

### Deploying the Group Role Map Builder

Run `make deploy-group-role-map-builder` to package up the [functions](https://github.com/mozilla-iam/mozilla-aws-cli/tree/master/cloudformation/group_role_map_builder/functions)
and the [CloudFormation template](https://github.com/mozilla-iam/mozilla-aws-cli/blob/master/cloudformation/group_role_map_builder/group_role_map_builder.yaml)
and deploy the stack into AWS using CloudFormation

## ID Token For Roles API

The ID Token For Role API is an API with three slightly related endpoints

-   The `/roles`  endpoint enables a user to exchange an OAuth2 ID Token that
    they've been issued for a list of their groups and the IAM Roles they have 
    access to. This is how a user queries the data that the Group Role Map 
    Builder produces. This is needed so that a user can see a UI of the IAM 
    Roles that they have access to in order to pick one.
-   The `/account-aliases`  endpoint allows anyone to get a map of AWS Account 
    IDs to AWS Account aliases. The map is generated by the Group Role Map 
    Builder. This endpoint is unauthenticated
-   The `/rebuild-group-role-map` endpoint triggers the Group Role Map Builder 
    to scan all AWS accounts and update the Group Role Map data. This is used 
    to avoid waiting the 10 minutes for the scheduled rebuild to occur. Only 
    authenticated LDAP users can trigger this endpoint.

The API is an AWS API Gateway in front of AWS Lambda.

In order for a user to use the `/roles`  or `/rebuild-group-role-map`  endpoints 
they must submit an ID token and key which

-   are cryptographically valid
-   aren't expired
-   are issued by Mozilla's Auth0 instance
-   are issued for AWS
-   contain an `amr`  fields

Additionally, the `/rebuild-group-role-map` endpoint requires that

-   the user have a `sub`  which [begins with `ad|Mozilla-LDAP|`](https://github.com/mozilla-iam/mozilla-aws-cli/blob/6de1d9223f14d2ad5cae85856e2c7036ab8237eb/cloudformation/Makefile#L82) 
    which [constrains this endpoint to only Mozilla employees](https://github.com/mozilla-iam/mozilla-aws-cli/blob/6de1d9223f14d2ad5cae85856e2c7036ab8237eb/cloudformation/idtoken_for_roles/functions/idtoken_for_roles.py#L173-L174)

This means that [anyone who is permitted](https://github.com/mozilla-iam/sso-dashboard-configuration/blob/fae0edbfcf11b0fdfb6161289df500e5cf9bd713/apps.yml#L2426-L2431)
to use Mozilla's federated AWS system can fetch their groups and roles and 
employees can trigger a Group Role Map Rebuild.

By default, the `/roles` and `/account-aliases`  endpoints use caching to avoid 
fetching the Group Role Map or alias data. A user can bypass this cache by 
passing a `cache=false` query parameter.

More Mozilla specific information can be found in [internal documentation](https://mana.mozilla.org/wiki/display/SECURITY/AWS+Federated+Login+with+Single+Sign+On)

### Deploying the ID Token For Roles API

The ID Tokens for Roles API can be deployed in any AWS account or region

To deploy it

-   Checkout the [https://github.com/mozilla-iam/mozilla-aws-cli](https://github.com/mozilla-iam/mozilla-aws-cli) repo
-   In the [`cloudformation`  directory](https://github.com/mozilla-iam/mozilla-aws-cli/tree/master/cloudformation) run `make deploy-idtoken-for-roles`

which will package up the [functions](https://github.com/mozilla-iam/mozilla-aws-cli/tree/master/cloudformation/idtoken_for_roles/functions) 
into the [CloudFormation template](https://github.com/mozilla-iam/mozilla-aws-cli/blob/master/cloudformation/idtoken_for_roles/idtoken_for_roles.yaml) 
and deploy it using CloudFormation

