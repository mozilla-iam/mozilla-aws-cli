import boto3
from moto import mock_dynamodb2
from ..get_security_audit_role_arns import get_security_audit_role_arns
from ..get_security_audit_role_arns import (
    TABLE_CATEGORY,
    TABLE_INDEX_NAME,
    TABLE_ATTRIBUTE_NAME,
    TABLE_NAME,
    TABLE_REGION,
)

# https://github.com/mozilla/cloudformation-cross-account-outputs/blob/master/cloudformation/cloudformation-stack-emissions-dynamodb.yml
TABLE_PRIMARY_HASH_ATTRIBUTE = 'aws-account-id'
TABLE_PRIMARY_RANGE_ATTRIBUTE = 'id'
TABLE_SECONDARY_HASH_ATTRIBUTE = TABLE_INDEX_NAME
TABLE_SECONDARY_RANGE_ATTRIBUTE = TABLE_PRIMARY_RANGE_ATTRIBUTE

# Test values
AWS_ACCOUNT_ID = '123456789012'
IAM_ROLE_NAME = (
    'InfosecClientRoleSecurity-InfosecSecurityAuditRole-ABCDEFGHIJKLM'
)
IAM_ROLE_ARN = 'arn:aws:iam::{}:role/{}'.format(AWS_ACCOUNT_ID, IAM_ROLE_NAME)
STACK_ID = '12345678-90ab-cdef-1234-567890abcdef'
LOGICAL_RESOURCE_ID = 'PublishInfosecSecurityAuditRoleArnToSNS'


def create_dynamodb_table():
    """Create a mocked CloudFormation Cross Account Output DynamoDB table

    https://github.com/mozilla/cloudformation-cross-account-outputs/blob/master/cloudformation/cloudformation-stack-emissions-dynamodb.yml
    """
    client = boto3.client('dynamodb', region_name=TABLE_REGION)
    client.create_table(
        AttributeDefinitions=[
            {
                'AttributeName': TABLE_PRIMARY_HASH_ATTRIBUTE,
                'AttributeType': 'S',
            },
            {
                'AttributeName': TABLE_PRIMARY_RANGE_ATTRIBUTE,
                'AttributeType': 'S',
            },
            {
                'AttributeName': TABLE_SECONDARY_HASH_ATTRIBUTE,
                'AttributeType': 'S',
            },
        ],
        TableName=TABLE_NAME,
        KeySchema=[
            {'AttributeName': TABLE_PRIMARY_HASH_ATTRIBUTE, 'KeyType': 'HASH'},
            {
                'AttributeName': TABLE_PRIMARY_RANGE_ATTRIBUTE,
                'KeyType': 'RANGE',
            },
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': TABLE_SECONDARY_HASH_ATTRIBUTE,
                'KeySchema': [
                    {
                        'AttributeName': TABLE_SECONDARY_HASH_ATTRIBUTE,
                        'KeyType': 'HASH',
                    },
                    {
                        'AttributeName': TABLE_SECONDARY_RANGE_ATTRIBUTE,
                        'KeyType': 'RANGE',
                    },
                ],
                'Projection': {'ProjectionType': 'ALL'},
            }
        ],
        BillingMode='PAY_PER_REQUEST',
    )


def add_records_to_table():
    """Add testing data to mocked DynamoDB table"""
    item = {
        TABLE_PRIMARY_HASH_ATTRIBUTE: AWS_ACCOUNT_ID,
        TABLE_INDEX_NAME: TABLE_CATEGORY,
        TABLE_PRIMARY_RANGE_ATTRIBUTE: '{}+{}'.format(
            STACK_ID, LOGICAL_RESOURCE_ID
        ),
        'last-updated': '2019-02-07T18:40:44.525270Z',
        'logical-resource-id': LOGICAL_RESOURCE_ID,
        'region': 'us-west-2',
        TABLE_ATTRIBUTE_NAME: IAM_ROLE_ARN,
        'SecurityAuditIAMRoleName': IAM_ROLE_NAME,
        'stack-id': STACK_ID,
        'stack-name': 'InfosecClientRoleSecurityAudit',
    }
    dynamodb = boto3.resource('dynamodb', region_name=TABLE_REGION)
    table = dynamodb.Table(TABLE_NAME)
    table.put_item(Item=item)


@mock_dynamodb2
def test_get_security_audit_role_arns():
    """Create a table, populate it then fetch IAM Role ARNs"""
    create_dynamodb_table()
    add_records_to_table()
    arns = get_security_audit_role_arns()
    assert IAM_ROLE_ARN in arns
