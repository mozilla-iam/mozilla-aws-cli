from typing import Dict, Tuple, Optional
import json
import os
import logging
import traceback
from datetime import tzinfo, timedelta, datetime
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
ALLOWED_MAP_BUILDER_SUB_PREFIX = os.getenv(
    'ALLOWED_MAP_BUILDER_SUB_PREFIX', False)
GROUP_ROLE_MAP_BUILDER_FUNCTION_NAME = os.getenv(
    'GROUP_ROLE_MAP_BUILDER_FUNCTION_NAME')

METHOD_NOT_ALLOWED = {
    'headers': {'Content-Type': 'text/html'},
    'statusCode': 405,
    'body': '405 Method Not Allowed'}

ZERO = timedelta(0)


class UTC(tzinfo):
    def utcoffset(self, dt):
        return ZERO
    def tzname(self, dt):
        return "UTC"
    def dst(self, dt):
        return ZERO

utc = UTC()

SimpleDict = Dict[str, str]
DictOfLists = Dict[str, list]
TokenValidationError = type('TokenValidationError', (ValueError,), dict())


def validate_token(token, key):
    required_env_variables = {'ALLOWED_ISSUER', 'ALLOWED_AUDIENCE'}
    if not required_env_variables.issubset(set(os.environ)):
        missing_env_variables = (
                required_env_variables -
                required_env_variables.intersection(set(os.environ)))
        raise TokenValidationError(
            'Environment variables {} not set in idtoken_for_roles. Contact '
            'the IAM administrators.'.format(missing_env_variables))
    try:
        id_token = jwt.decode(
            token=token,
            key=key,
            audience=os.getenv('ALLOWED_AUDIENCE'),
            issuer=os.getenv('ALLOWED_ISSUER'),
        )
    except exceptions.ExpiredSignatureError as e:
        logger.error('Expired JWT signature : {}'.format(e))
        raise TokenValidationError('Expired JWT signature')
    except exceptions.JWTClaimsError as e:
        logger.error('Invalid claims in ID Token (allowed audience {} allowed issuer {}) : {}'.format(os.getenv('ALLOWED_AUDIENCE'), os.getenv('ALLOWED_ISSUER'), e))
        raise TokenValidationError('Invalid claims in ID Token')
    except exceptions.JWTError as e:
        logger.error('Invalid JWT signature : {}'.format(e))
        raise TokenValidationError('Invalid JWT signature')
    if 'amr' not in id_token:
        logger.error('amr claim missing from ID Token : {}'.format(id_token))
        raise TokenValidationError('amr claim missing from ID Token')
    return id_token


def get_s3_file(
    s3_bucket: str,
    s3_key: str,
) -> Tuple[Optional[datetime], DictOfLists]:
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
            return None, dict()
        else:
            raise
    return response['LastModified'], json.load(response['Body'])


def get_roles_and_aliases(token, key, cache):
    global group_role_map
    global account_alias_map

    try:
        id_token = validate_token(token, key)
    except TokenValidationError as e:
        return {'error': str(e)}
    if (not cache) or ('group_role_map' not in globals()):
        logger.debug(
            'Group Role Map was not found in globals, refetching from S3')
        _, group_role_map = get_s3_file(
            S3_BUCKET_NAME, S3_FILE_PATH_GROUP_ROLE_MAP)
    if (not cache) or ('account_alias_map' not in globals()):
        logger.debug(
            'Account Alias Map was not found in globals, refetching from S3')
        _, account_alias_map = get_s3_file(
            S3_BUCKET_NAME, S3_FILE_PATH_ALIAS_MAP)
    roles = set()
    aliases = {}
    for group, mapped_roles in group_role_map.items():
        if group in id_token['amr']:
            for role in mapped_roles:
                aws_account_id = role.split(':')[4]
                if (aws_account_id in account_alias_map
                        and aws_account_id not in aliases):
                    logger.debug('Group {} found in AMR {} adding AWS Account '
                                 'alias {} for account {}'.format(
                        group,
                        id_token['amr'],
                        account_alias_map[aws_account_id],
                        aws_account_id))
                    aliases[aws_account_id] = account_alias_map[aws_account_id]
            roles.update(mapped_roles)
        else:
            logger.debug('Group {} not in amr {}'.format(
                group, id_token['amr']))
    return {'roles': list(roles), 'aliases': aliases}


def get_aliases(cache):
    global account_alias_map
    if (not cache) or ('account_alias_map' not in globals()):
        logger.debug(
            'Account Alias Map was not found in globals, refetching from S3')
        _, account_alias_map = get_s3_file(
            S3_BUCKET_NAME, S3_FILE_PATH_ALIAS_MAP)
    return account_alias_map


def initiate_group_role_map_rebuild(token, key):
    try:
        id_token = validate_token(token, key)
    except TokenValidationError as e:
        return {'error': str(e)}
    if not ALLOWED_MAP_BUILDER_SUB_PREFIX:
        return {'error': 'ALLOWED_MAP_BUILDER_SUB_PREFIX is unset'}
    if not id_token.get('sub', '').startswith(ALLOWED_MAP_BUILDER_SUB_PREFIX):
        return {'error': 'User is not permitted'}
    if GROUP_ROLE_MAP_BUILDER_FUNCTION_NAME is None:
        return {'error': 'GROUP_ROLE_MAP_BUILDER_FUNCTION_NAME is unset'}
    group_role_map_last_modified, group_role_map = get_s3_file(
        S3_BUCKET_NAME, S3_FILE_PATH_GROUP_ROLE_MAP)
    logger.debug('datetime.now(utc) is {} and group_role_map_last_modified is {}'.format(datetime.now(utc), group_role_map_last_modified))
    group_role_map_age = datetime.now(utc) - group_role_map_last_modified
    # TODO : Here's the problem. This comparison is between the last time the file changed and now
    # and the file isn't updated if nothing changed
    # so this doesn't stop someone from invoking over and over again
    # we need make group role map buider touch a file or something indicating that a scan has been done
    # despite the fact that the json map hasn't changed
    # or persist this state here in idtokenforroles some other way
    seconds_until_next_allowed_rebuild = max(
        0, (60 * 5) - int(group_role_map_age.total_seconds()))
    if seconds_until_next_allowed_rebuild > 0:
        return {
            'error': 'It has been less than 5 minutes since the last rebuild. '
                     'You must wait another {} seconds before '
                     'rebuilding.'.format(seconds_until_next_allowed_rebuild)}
    client = boto3.client('lambda')
    response = client.invoke(
        FunctionName=GROUP_ROLE_MAP_BUILDER_FUNCTION_NAME,
        InvocationType='Event',
    )
    logger.info('User {} initiated a group role map rebuild'.format(
        id_token.get('sub')))
    if response.get('FunctionError'):
        logger.error('group role map rebuild invocation returned {}'.format(
            response.get('FunctionError')
        ))
    return {'status': 'success : {}'.format(response.get('StatusCode'))}


def lambda_handler(event, context):
    logger.debug("event type is {} and event is {}".format(type(event), event))
    try:
        params = (event['queryStringParameters']
                  if event['queryStringParameters'] is not None else {})
        body = event.get('body')
        payload = json.loads(body) if body is not None else {}
        if event.get('path') == '/account-aliases':
            if event.get('httpMethod') != 'GET':
                return METHOD_NOT_ALLOWED
            return {
                'headers': {'Content-Type': 'application/json'},
                'statusCode': 200,
                'body': json.dumps(get_aliases(params.get('cache', True)))}
        elif event.get('path') == '/roles':
            if event.get('httpMethod') != 'POST':
                return METHOD_NOT_ALLOWED

            return {
                'headers': {'Content-Type': 'application/json'},
                'statusCode': 200,
                'body': json.dumps(get_roles_and_aliases(
                    payload.get('token'),
                    payload.get('key'),
                    payload.get('cache', True)))}
        elif event.get('path') == '/rebuild-group-role-map':
            if event.get('httpMethod') != 'POST':
                return METHOD_NOT_ALLOWED
            return {
                'headers': {'Content-Type': 'application/json'},
                'statusCode': 200,
                'body': json.dumps(initiate_group_role_map_rebuild(
                    payload.get('token'),
                    payload.get('key')))}
        else:
            return {
                'headers': {'Content-Type': 'text/html'},
                'statusCode': 404,
                'body': '404 Not Found'}
    except Exception as e:
        logger.error(str(e))
        logger.error(traceback.format_exc())
        return {
            'headers': {'Content-Type': 'text/html'},
            'statusCode': 500,
            'body': 'Error'}
