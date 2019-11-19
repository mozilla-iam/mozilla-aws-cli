from typing import Dict
import json
import os
import logging
import boto3
from jose import jwt, exceptions

logger = logging.getLogger()
logging.getLogger().setLevel(os.getenv('LOG_LEVEL', 'INFO'))
logging.getLogger('boto3').propagate = False
logging.getLogger('botocore').propagate = False
logging.getLogger('urllib3').propagate = False

# AWS Account : infosec-prod
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
S3_FILE_PATH_GROUP_ROLE_MAP = os.getenv(
    'S3_FILE_PATH_GROUP_ROLE_MAP', 'access-group-iam-role-map.json')
S3_FILE_PATH_ALIAS_MAP = os.getenv(
    'S3_FILE_PATH_ALIAS_MAP', 'account-aliases.json')


SimpleDict = Dict[str, str]
DictOfLists = Dict[str, list]


def get_s3_file(
    s3_bucket: str,
    s3_key: str,
) -> DictOfLists:
    """Fetch a map from S3

    :param str s3_bucket: The name of the S3 bucket to store the file in
    :param str s3_key: The path and filename in the S3 bucket to store the file
                       in
    :return: Parsed content of the group role map file (a dict of lists)
    """
    client = boto3.client('s3')
    kwargs = {'Bucket': s3_bucket, 'Key': s3_key}
    try:
        logger.debug('Fetching S3 file with args {}'.format(kwargs))
        response = client.get_object(**kwargs)
    except client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return dict()
        else:
            raise
    return json.load(response['Body'])


def get_roles_and_aliases(token, key, cache):
    global group_role_map
    global account_alias_map

    required_env_variables = {'ALLOWED_ISSUER', 'ALLOWED_AUDIENCE'}
    if not required_env_variables.issubset(set(os.environ)):
        missing_env_variables = (
                required_env_variables -
                required_env_variables.intersection(set(os.environ)))
        error_message = (
            'Environment variables {} not set in idtoken_for_roles. Contact '
            'the IAM administrators.')
        return {'error': error_message.format(missing_env_variables)}
    try:
        id_token = jwt.decode(
            token=token,
            key=key,
            audience=os.getenv('ALLOWED_AUDIENCE'),
            issuer=os.getenv('ALLOWED_ISSUER'),
        )
    except exceptions.ExpiredSignatureError as e:
        return {'error': 'Expired JWT signature : {}'.format(e)}
    except exceptions.JWTClaimsError as e:
        return {'error': 'Invalid claims in ID Token : {}'.format(e)}
    except exceptions.JWTError as e:
        return {'error': 'Invalid JWT signature : {}'.format(e)}
    if 'amr' not in id_token:
        return {'error': 'amr claim missing from ID Token'}
    if (not cache) or ('group_role_map' not in globals()):
        logger.debug(
            'Group Role Map was not found in globals, refetching from S3')
        group_role_map = get_s3_file(
            S3_BUCKET_NAME, S3_FILE_PATH_GROUP_ROLE_MAP)
    if (not cache) or ('account_alias_map' not in globals()):
        logger.debug(
            'Account Alias Map was not found in globals, refetching from S3')
        account_alias_map = get_s3_file(S3_BUCKET_NAME, S3_FILE_PATH_ALIAS_MAP)
    roles = set()
    aliases = {}
    for group, mapped_roles in group_role_map.items():
        if group in id_token.get('amr', []):
            for role in mapped_roles:
                aws_account_id = role.split(':')[4]
                if (aws_account_id in account_alias_map
                        and aws_account_id not in aliases):
                    aliases[aws_account_id] = account_alias_map[
                        aws_account_id]
            roles.update(mapped_roles)
        else:
            logger.debug('Group {} not in amr {}'.format(
                group, id_token.get('amr')))
    return {'roles': list(roles), 'aliases': aliases}


def get_aliases(cache):
    global account_alias_map
    if (not cache) or ('account_alias_map' not in globals()):
        logger.debug(
            'Account Alias Map was not found in globals, refetching from S3')
        account_alias_map = get_s3_file(S3_BUCKET_NAME, S3_FILE_PATH_ALIAS_MAP)
    return account_alias_map


def lambda_handler(event, context):
    logger.debug("event type is {} and event is {}".format(type(event), event))

    token = event.get('token')
    key = event.get('key')
    cache = event.get('cache', True)
    if token and key:
        return get_roles_and_aliases(token, key, cache)
    else:
        return get_aliases(cache)
