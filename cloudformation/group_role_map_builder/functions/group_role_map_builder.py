from typing import Dict, List, Optional, Tuple
import collections
import json
from json.decoder import JSONDecodeError
import hashlib
import os
import logging
import boto3

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)
logging.getLogger('boto3').propagate = False
logging.getLogger('botocore').propagate = False
logging.getLogger('urllib3').propagate = False

DEFAULTS = {
    'TABLE_CATEGORY': 'AWS Security Auditing Service',
    'TABLE_INDEX_NAME': 'category',
    'TABLE_ATTRIBUTE_NAME': 'SecurityAuditIAMRoleArn',
    'TABLE_NAME': 'cloudformation-stack-emissions',
    'TABLE_REGION': 'us-west-2',
    'S3_BUCKET_NAME': None,
    'S3_FILE_PATH_GROUP_ROLE_MAP': 'access-group-iam-role-map.json',
    'S3_FILE_PATH_ALIAS_MAP': 'account-aliases.json',
    'VALID_AMRS': '',
    'VALID_FEDERATED_PRINCIPAL_URLS': '',
}
COMMA_DELIMITED_VARIABLES = ['VALID_AMRS', 'VALID_FEDERATED_PRINCIPAL_URLS']
UNGLOBBABLE_OPERATORS = ("StringEquals", "ForAnyValue:StringEquals")
UNSUPPORTED_OPERATORS = (
    "StringNotEquals",
    "ForAnyValue:StringNotEquals",
    "StringNotLike",
    "ForAnyValue:StringNotLike",
)
VALID_OPERATORS = (
    "StringEquals",
    "ForAnyValue:StringEquals",
    "StringLike",
    "ForAnyValue:StringLike",
)

# via : https://tools.ietf.org/html/rfc4287#section-4.2.7.2
S3_FILE_LINK_HEADER = os.getenv(
    'S3_FILE_LINK_HEADER',
    '<https://github.com/mozilla-iam/mozilla-aws-cli/tree/master/'
    'cloudformation>; rel="via"',
)

SimpleDict = Dict[str, str]
DictOfLists = Dict[str, list]
TupleOfDictOflists = Tuple[DictOfLists, DictOfLists]


class InvalidPolicyError(Exception):
    pass


class UnsupportedPolicyError(Exception):
    pass


class MozDefMessageStub:
    """This is a placeholder stub class which goes away when we switch to
    libmozdef"""

    def __init__(
        self,
        summary,
        source,
        hostname='',
        severity='INFO',
        category='event',
        processid=1,
        processname='',
        tags=None,
        details=None,
        timestamp=None,
        utctimestamp=None,
    ):
        pass

    def send(self, pathway=None, validator=None):
        return True


def get_setting(name):
    value = os.getenv(name, DEFAULTS.get(name))
    if name in COMMA_DELIMITED_VARIABLES:
        return list(filter(None, value.split(',')))
    else:
        return value


def is_valid_identity_provider(arn):
    return (
        arn[:13] == 'arn:aws:iam::'
        and arn[25:40] == ':oidc-provider/'
        and arn[40:] in
        [x[8:] for x in get_setting('VALID_FEDERATED_PRINCIPAL_URLS')])


def get_paginated_results(
    product: str,
    action: str,
    key: str,
    client_args: Optional[SimpleDict] = None,
    action_args: Optional[SimpleDict] = None,
) -> list:
    """Paginate through AWS API responses, combining them into a list

    :param str product: AWS product name
    :param str action: AWS API action name
    :param str key: The parent key in the paginated response
    :param dict client_args: Optional AWS API credentials
    :param dict action_args: Optional additional arguments to pass to action
                             method
    :return: list of responses from all pages
    """
    action_args = {} if action_args is None else action_args
    client_args = {} if client_args is None else client_args
    return [
        response_element
        for sublist in [
            api_response[key]
            for api_response in boto3.client(product, **client_args)
            .get_paginator(action)
            .paginate(**action_args)
        ]
        for response_element in sublist
    ]


def flip_map(dict_of_lists: DictOfLists) -> DictOfLists:
    """Flip a map of keys to lists to a map of list elements to lists of keys

    Flips an input like

    {'arn:aws:iam::123...': ['team_foo', 'team_bar'],
     'arn:aws:iam::456...': ['team_baz', 'team_bar']}

    and returns

    {'team_foo': ['arn:aws:iam::123...'],
     'team_bar': ['arn:aws:iam::123...', 'arn:aws:iam::456...'],
     'team_baz': ['arn:aws:iam::456...']}

    :param dict dict_of_lists: dictionary of lists
    :return: The flipped map
    """
    group_arn_map = collections.defaultdict(list)
    for arn in dict_of_lists:
        for group in dict_of_lists[arn]:
            group_arn_map[group].append(arn)
    return group_arn_map


def emit_event_to_mozdef(
    new_map: DictOfLists,
    existing_map: DictOfLists
):
    """Build and emit an event to MozDef about changes to IAM roles

    :param dict new_map: The new map file
    :param dict existing_map: The existing map file
    :return:
    """
    new_groups = set(new_map) - set(existing_map)
    deleted_groups = set(existing_map) - set(new_map)
    new_arn_group_map = flip_map(new_map)
    existing_arn_group_map = flip_map(existing_map)
    new_roles = set(new_arn_group_map) - set(existing_arn_group_map)
    deleted_roles = set(existing_arn_group_map) - set(new_arn_group_map)
    changed_roles = {}
    for role, groups in new_arn_group_map.items():
        if role in existing_arn_group_map:
            if len(set(groups) ^ set(existing_arn_group_map[role])) > 0:
                changed_roles[role] = {
                    'new_groups': set(groups),
                    'old_groups': set(existing_arn_group_map[role]),
                }
    if (
        new_groups
        or deleted_groups
        or new_roles
        or deleted_roles
        or changed_roles
    ):
        accounts_affected = set(
            map(
                lambda x: x.split(':')[4],
                set(new_roles) | set(deleted_roles) | set(changed_roles),
            )
        )
        summary = (
            'Changes detected with AWS IAM roles used for federated access in '
            'AWS accounts {}'.format(', '.join(accounts_affected))
        )
        source = 'federated-aws'
        category = 'aws-auth'
        details = dict()
        if new_groups:
            details['new-groups'] = new_groups
        if deleted_groups:
            details['deleted-groups'] = deleted_groups
        if new_roles:
            details['new-roles'] = new_roles
        if deleted_roles:
            details['deleted-roles'] = deleted_roles
        if changed_roles:
            details['changed-roles'] = changed_roles
        message = MozDefMessageStub(
            summary=summary, source=source, category=category, details=details
        )
        message.send()
        # TODO : Add call to libmozdef once it's published in pypi
        # to emit an event to MozDef with this data


def get_groups_from_policy(policy) -> list:
    # groups will be stored as a set to prevent duplicates and then return
    # a list when everything is finished
    policy_groups = set()

    # be flexible on being passed a dictionary (parsed policy) or a string
    # (unparsed policy)
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except JSONDecodeError:
            logger.error("InvalidPolicyError : Can't parse JSON")
            raise InvalidPolicyError

    if not isinstance(policy, dict):
        logger.error("InvalidPolicyError : Policy is not dict")
        raise InvalidPolicyError

    # If policy lacks a statement, we can bail out
    if 'Statement' not in policy:
        logger.debug('Skipping policy as it has no statements')
        return []

    for statement in policy["Statement"]:
        if statement.get("Effect", '').lower() != "Allow".lower():
            logger.debug(
                'Skipping policy statement with Effect {}'.format(
                    statement.get("Effect")))
            continue
        if (statement.get("Action", '').lower()
                != "sts:AssumeRoleWithWebIdentity".lower()):
            # logger.debug(
            #     'Skipping policy statement with Action {}'.format(
            #         statement.get("Action")))
            continue

        if not is_valid_identity_provider(
                statement.get('Principal', {}).get('Federated')):
            logger.debug(
                'Skipping policy statement with Federated Principal {} which '
                'is not valid'.format(
                    statement.get('Principal', {}).get('Federated')))
            continue
        operator_count = 0
        for operator in statement.get("Condition", {}).keys():
            # StringNotLike, etc. are not supported
            if operator in UNSUPPORTED_OPERATORS:
                logger.error(
                    'UnsupportedPolicyError'
                    ': Condition uses operator {}'.format(operator))
                raise UnsupportedPolicyError
            # Is a valid operator and contains a valid :amr entry
            elif operator in VALID_OPERATORS and any(
                amr in get_setting('VALID_AMRS')
                for amr in statement["Condition"][operator].keys()
            ):
                operator_count += 1

        # Multiple operators are not supported
        if operator_count > 1:
            logger.error(
                'UnsupportedPolicyError : Too many ({}) operators used'.format(
                    operator_count))
            raise UnsupportedPolicyError

        # An absence of operators means all users are permitted which isn't
        # supported
        if operator_count == 0:
            logger.error(
                'UnsupportedPolicyError : Statement has no amr conditions, '
                'all users permitted access. At least one amr condition is '
                'required')
            raise UnsupportedPolicyError

        # For clarity:
        # operator --> StringEquals, ForAnyValue:StringLike
        # conditions --> dictionary mapping, e.g. StringEquals: {}
        # condition: auth-dev.mozilla.auth0.com/:amr
        for operator, conditions in statement.get("Condition", {}).items():
            for condition in conditions:
                if condition in get_setting('VALID_AMRS'):
                    groups = conditions[condition]
                    groups = [groups] if isinstance(groups, str) else groups

                    # Only the StringLike operator allows globbing or ?
                    # Technically the * and ? values are legal in StringEquals,
                    # but we don't allow them for clarity
                    if (operator in UNGLOBBABLE_OPERATORS
                            and set('*?') & set(''.join(groups))):
                        logger.error(
                            "InvalidPolicyError : Mismatched operator and "
                            "wildcards. Operator {} and groups {}".format(
                                operator, groups))
                        raise InvalidPolicyError

                    policy_groups.update(groups)

    return list(policy_groups)


def get_s3_file(
    s3_bucket: str,
    s3_key: str,
    new_map: Optional[DictOfLists] = None,
) -> DictOfLists:
    """Fetch a map from S3 unless it doesn't differ from the current one

    :param str s3_bucket: The name of the S3 bucket to store the file in
    :param str s3_key: The path and filename in the S3 bucket to store the file
                       in
    :param dict new_map: A dictionary mapping
    :return: Parsed content of the group role map file (a dict of lists)
    """
    client = boto3.client('s3')
    kwargs = {'Bucket': s3_bucket, 'Key': s3_key}
    if new_map is not None:
        new_map_serialized = serialize_map(new_map)
        kwargs['IfNoneMatch'] = hashlib.md5(new_map_serialized).hexdigest()
    try:
        logger.debug('Fetching S3 file with args {}'.format(kwargs))
        response = client.get_object(**kwargs)
    except client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '304':
            return new_map
        if e.response['Error']['Code'] == 'NoSuchKey':
            return dict()
        else:
            raise
    return json.load(response['Body'])


def serialize_map(input_map: DictOfLists) -> str:
    """Serialize a dictionary of lists in a consistent hashable format

    :param dict input_map: A dictionary mapping
    :return: A serialized JSON string
    """
    return json.dumps(input_map, sort_keys=True, indent=4).encode('utf-8')


def store_s3_file(s3_bucket: str,
                  s3_key: str,
                  new_map: DictOfLists,
                  emit_diff: bool = False) -> bool:
    """Compare the new file with the file stored in S3

    Store the new file and emit an event to MozDef if they differ. Return True
    if there was a change and False if not.

    :param str s3_bucket: The name of the S3 bucket to store the file in
    :param str s3_key: The path and filename in the S3 bucket to store the file
                       in
    :param dict new_map: A dictionary mapping
    :param bool emit_diff: Whether or not to emit an event to MozDef if the
                           new_map differs from what's stored in S3 already
    :return: True if the new map differs from the one stored, otherwise False
    """
    existing_map = get_s3_file(s3_bucket, s3_key, new_map)
    new_map_serialized = serialize_map(new_map)
    if serialize_map(existing_map) != new_map_serialized:
        if emit_diff:
            emit_event_to_mozdef(new_map, existing_map)
        client = boto3.client('s3')
        # Link : https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
        client.put_object(
            Body=new_map_serialized,
            Bucket=s3_bucket,
            ContentType='application/json',
            Key=s3_key,
            Metadata={'Link': S3_FILE_LINK_HEADER},
        )
        return True
    else:
        return False


def build_group_role_map(assumed_role_arns: List[str]) -> TupleOfDictOflists:
    """Build map of IAM roles to OIDC groups used in assumption policies.

    Given a list of IAM Role ARNs to assume, iterate over those roles,
    assuming each of them. Acting as each of these assumed roles, query for all
    IAM roles in that AWS account, passing each role's AssumeRolePolicyDocument
    to get_groups_from_policy to fetch a list of OIDC claim groups
    in that policy document. Return a map that looks like

    {
        'team_bar': [
            'arn:aws:iam::123456789012:role/role-for-anyone-but-team-bar',
            'arn:aws:iam::123456789012:role/project-baz-role'
        ],
        'team_foo': [
            'arn:aws:iam::123456789012:role/role-for-team-foo',
            'arn:aws:iam::123456789012:role/project-baz-role'
        ]
    }

    :param list assumed_role_arns: list of IAM role ARN strings
    :return: a tuple of the map of IAM ARNs to related OIDC claimed group names
             followed by the map of AWS account IDs to account aliases
    """
    assumed_role_credentials = {}
    role_group_map = {}
    alias_map = {}
    for assumed_role_arn in assumed_role_arns:
        aws_account_id = assumed_role_arn.split(':')[4]
        logger.debug('Fetching policies from {}'.format(aws_account_id))
        client_sts = boto3.client('sts')
        limiting_policy = {
            'Version': '2012-10-17',
            'Statement': [
                {'Effect': 'Allow',
                 'Action': ['iam:ListRoles', 'iam:ListAccountAliases'],
                 'Resource': '*'}
            ],
        }
        try:
            response = client_sts.assume_role(
                RoleArn=assumed_role_arn,
                RoleSessionName='Federated-Login-Policy-Collector',
                Policy=json.dumps(limiting_policy),
            )
        except client_sts.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.error(
                    'AWS Account {} IAM role {} is not assumable : {}'.format(
                        aws_account_id, assumed_role_arn, e))
            continue
        assumed_role_credentials[aws_account_id] = {
            'aws_access_key_id': response['Credentials']['AccessKeyId'],
            'aws_secret_access_key': response['Credentials'][
                'SecretAccessKey'
            ],
            'aws_session_token': response['Credentials']['SessionToken'],
        }
        roles = get_paginated_results(
            'iam',
            'list_roles',
            'Roles',
            assumed_role_credentials[aws_account_id],
        )
        aliases = get_paginated_results(
            'iam',
            'list_account_aliases',
            'AccountAliases',
            assumed_role_credentials[aws_account_id],
        )
        for role in roles:
            try:
                logger.debug(
                    'Checking assume role policy document for role {} in AWS '
                    'account {}'.format(role['RoleName'], aws_account_id))
                groups = get_groups_from_policy(
                    role['AssumeRolePolicyDocument'])
            except UnsupportedPolicyError:
                # a policy intended to work with the right IdP but with
                #   conditions beyond what we can handle
                # a policy intended to work with the right IdP but with no
                #   conditions resulting in allowing all users to assume the
                #   role

                # TODO : Emit a MozDef event reporting this unsupported policy
                continue
            except InvalidPolicyError:
                # a policy which isn't valid JSON which should never happen
                # a policy which isn't a dictionary which should never happen
                # a policy with a StringEquals condition where the value
                #   contains wildcard characters
                #     this is either a mistake and the author intended
                #     StringLike not String equals or
                #     this is not a mistake and the author is trying to match
                #     a group name with a literal "?" or "*" character in the
                #     group name

                # TODO : Emit a MozDef event reporting this invalid policy
                continue
            role_group_map[role['Arn']] = groups
        alias_map[aws_account_id] = aliases
    return flip_map(role_group_map), alias_map


def get_security_audit_role_arns() -> List[str]:
    """Fetch list ARNs of security auditing IAM Roles

    :return: List of ARNs
    """
    action_args = {
        'TableName': get_setting('TABLE_NAME'),
        'IndexName': get_setting('TABLE_INDEX_NAME'),
        'Select': 'SPECIFIC_ATTRIBUTES',
        'ProjectionExpression': get_setting('TABLE_ATTRIBUTE_NAME'),
        'KeyConditionExpression': '#c = :v',
        'ExpressionAttributeNames': {'#c': get_setting('TABLE_INDEX_NAME')},
        'ExpressionAttributeValues': {
            ':v': {'S': get_setting('TABLE_CATEGORY')}},
    }
    items = get_paginated_results(
        'dynamodb',
        'query',
        'Items',
        {'region_name': get_setting('TABLE_REGION')},
        action_args,
    )
    return [
        x[get_setting('TABLE_ATTRIBUTE_NAME')]['S']
        for x in items
        if get_setting('TABLE_ATTRIBUTE_NAME') in x
    ]


def lambda_handler(event, context):
    security_audit_role_arns = get_security_audit_role_arns()
    logger.debug(
        'IAM Role ARNs fetched from table : {}'.format(
            security_audit_role_arns
        )
    )
    group_role_map, alias_map = build_group_role_map(security_audit_role_arns)
    group_role_map_changed = store_s3_file(
        get_setting('S3_BUCKET_NAME'),
        get_setting('S3_FILE_PATH_GROUP_ROLE_MAP'),
        group_role_map,
        True)
    alias_map_changed = store_s3_file(
        get_setting('S3_BUCKET_NAME'),
        get_setting('S3_FILE_PATH_ALIAS_MAP'),
        alias_map,
        False)
    if group_role_map_changed:
        logger.info('Group role map in S3 updated : {}'.format(
            serialize_map(group_role_map)))
    if alias_map_changed:
        logger.info('Account alias map in S3 updated : {}'.format(
            serialize_map(alias_map)))

    return group_role_map
