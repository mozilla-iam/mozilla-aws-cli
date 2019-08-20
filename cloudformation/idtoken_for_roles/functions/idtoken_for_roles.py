from typing import Dict
import json
import os
import logging
import boto3

logger = logging.getLogger(__name__)
logging.getLogger().setLevel(logging.INFO)
logging.getLogger('boto3').propagate = False
logging.getLogger('botocore').propagate = False
logging.getLogger('urllib3').propagate = False

# AWS Account : infosec-prod
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
S3_FILE_PATH = os.getenv('S3_FILE_PATH', 'access-group-iam-role-map.json')

SimpleDict = Dict[str, str]
DictOfLists = Dict[str, list]


def get_group_role_map() -> DictOfLists:
    """Fetch the group role map from S3

    :return: Parsed content of the group role map file (a dict of lists)
    """
    client = boto3.client('s3')
    kwargs = {'Bucket': S3_BUCKET_NAME, 'Key': S3_FILE_PATH}
    try:
        logger.debug('Fetching S3 file with args {}'.format(kwargs))
        response = client.get_object(**kwargs)
    except client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return dict()
        else:
            raise
    return json.load(response['Body'])


def lambda_handler(event, context):
    body = event.get('body')
    print("body type is {} and content is {}".format(type(body), body))
    # payload = json.loads(event['body'])
    # id_token_dict = jwt.decode(
    #     token=tokens["id_token"],
    #     key=config["jwks"],
    #     audience=config["client_id"])
    return {'bar': 'foo'}


# if 'group_role_map' not in globals():
#     group_role_map = get_group_role_map()
