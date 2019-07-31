import json
import hashlib
from typing import Dict, Iterable, Optional
import boto3
from .build_group_role_map import flip_map

S3_BUCKET_NAME = 'mozilla-infosec-auth0-rule-assets'
FILE_PATH = 'access-group-iam-role-map.json'

# via : https://tools.ietf.org/html/rfc4287#section-4.2.7.2
LINK_HEADER = (
    '<https://github.com/mozilla-iam/federated-aws-cli/tree/master'
    '/cloudformation>; rel="via"'
)
DictOfLists = Dict[str, list]


class MozDefMessageStub():
    """This is a placeholder stub class which goes away when we switch to
    libmozdef"""
    def __init__(self,
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
                 utctimestamp=None
                 ):
        pass

    def send(self, pathway=None, validator=None):
        return True


def emit_event_to_mozdef(
    new_groups: Iterable[str],
    deleted_groups: Iterable[str],
    new_roles: Iterable[str],
    deleted_roles: Iterable[str],
    changed_roles: Dict[str, Iterable[str]],
):
    """Build and emit an event to MozDef about changes to IAM roles

    :param list new_groups: New OIDC claim groups present in role conditions
    :param list deleted_groups: OIDC claim groups previously present in role
                conditions
    :param list new_roles: New IAM roles which use federated login
    :param list deleted_roles: IAM roles using federated login which previously
                               existed
    :param list changed_roles: IAM roles using federated login that have
                               changed conditions
    :return:
    """
    accounts_affected = set(
        map(
            lambda x: x.split(':')[4],
            set(new_roles) | set(deleted_roles) | set(changed_roles),
        )
    )
    summary = (
        'Changes detected with AWS IAM roles used for federated access in AWS '
        'accounts {}'.format(', '.join(accounts_affected))
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
        summary=summary,
        source=source,
        category=category,
        details=details
    )
    message.send()
    # TODO : Add call to libmozdef once it's published in pypi
    # to emit an event to MozDef with this data


def get_group_role_map(
    new_group_arn_map: Optional[DictOfLists] = None
) -> DictOfLists:
    """Fetch the group role map from S3 unless it doesn't differ from the
    current one

    :param dict new_group_arn_map: A dictionary mapping groups to lists of
                                   roles
    :return: Parsed content of the group role map file (a dict of lists)
    """
    client = boto3.client('s3')
    kwargs = {'Bucket': S3_BUCKET_NAME, 'Key': FILE_PATH}
    if new_group_arn_map is not None:
        new_map_serialized = serialize_group_role_map(new_group_arn_map)
        kwargs['IfNoneMatch'] = hashlib.md5(new_map_serialized).hexdigest()
    try:
        response = client.get_object(**kwargs)
    except client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '304':
            return new_group_arn_map
        if e.response['Error']['Code'] == 'NoSuchKey':
            return dict()
        else:
            raise
    return json.load(response['Body'])


def serialize_group_role_map(group_role_map: DictOfLists) -> str:
    """Serialize a dictionary of lists in a consistent hashable format

    :param dict group_role_map: A dictionary mapping groups to lists of roles
    :return: A serialized JSON string
    """
    return json.dumps(group_role_map, sort_keys=True, indent=4).encode('utf-8')


def store_group_arn_map(new_group_arn_map: DictOfLists) -> bool:
    """Compare the new group ARN map with the existing map stored in S3

    Store the new map and emit an event to MozDef if they differ. Return True
    if there was a change and False if not.

    :param dict new_group_arn_map: A dictionary mapping groups to lists of
                                   roles
    :return: True if the new map differs from the one stored, otherwise False
    """
    existing_group_arn_map = get_group_role_map(new_group_arn_map)
    if existing_group_arn_map is False:
        # The new_map is the same as the existing_map
        return False
    new_groups = set(new_group_arn_map) - set(existing_group_arn_map)
    deleted_groups = set(existing_group_arn_map) - set(
        new_group_arn_map.keys()
    )
    new_arn_group_map = flip_map(new_group_arn_map)
    existing_arn_group_map = flip_map(existing_group_arn_map)
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
        emit_event_to_mozdef(
            new_groups, deleted_groups, new_roles, deleted_roles, changed_roles
        )
        new_map_serialized = serialize_group_role_map(new_group_arn_map)
        client = boto3.client('s3')
        # Link : https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
        client.put_object(
            Body=new_map_serialized,
            Bucket=S3_BUCKET_NAME,
            ContentType='application/json',
            Key=FILE_PATH,
            Metadata={'Link': LINK_HEADER},
        )
        return True
    else:
        return False
