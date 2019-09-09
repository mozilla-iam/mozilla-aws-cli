import boto3
from moto import mock_dynamodb2
from ..functions.group_role_map_builder import get_security_audit_role_arns
from ..functions.group_role_map_builder import get_setting

# https://github.com/mozilla/cloudformation-cross-account-outputs/blob/master/cloudformation/cloudformation-stack-emissions-dynamodb.yml
TABLE_PRIMARY_HASH_ATTRIBUTE = 'aws-account-id'
TABLE_PRIMARY_RANGE_ATTRIBUTE = 'id'
TABLE_SECONDARY_HASH_ATTRIBUTE = get_setting('TABLE_INDEX_NAME')
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
    client = boto3.client('dynamodb', region_name=get_setting('TABLE_REGION'))
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
        TableName=get_setting('TABLE_NAME'),
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
        get_setting('TABLE_INDEX_NAME'): get_setting('TABLE_CATEGORY'),
        TABLE_PRIMARY_RANGE_ATTRIBUTE: '{}+{}'.format(
            STACK_ID, LOGICAL_RESOURCE_ID
        ),
        'last-updated': '2019-02-07T18:40:44.525270Z',
        'logical-resource-id': LOGICAL_RESOURCE_ID,
        'region': 'us-west-2',
        get_setting('TABLE_ATTRIBUTE_NAME'): IAM_ROLE_ARN,
        'SecurityAuditIAMRoleName': IAM_ROLE_NAME,
        'stack-id': STACK_ID,
        'stack-name': 'InfosecClientRoleSecurityAudit',
    }
    dynamodb = boto3.resource(
        'dynamodb', region_name=get_setting('TABLE_REGION'))
    table = dynamodb.Table(get_setting('TABLE_NAME'))
    table.put_item(Item=item)


@mock_dynamodb2
def test_get_security_audit_role_arns():
    """Create a table, populate it then fetch IAM Role ARNs"""
    create_dynamodb_table()
    add_records_to_table()
    arns = get_security_audit_role_arns()
    assert IAM_ROLE_ARN in arns
