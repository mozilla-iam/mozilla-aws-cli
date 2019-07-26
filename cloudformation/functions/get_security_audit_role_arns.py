from typing import List
from .get_group_role_map import get_paginated_results

# AWS Account : infosec-prod
TABLE_CATEGORY = 'AWS Security Auditing Service'
TABLE_INDEX_NAME = 'category'
TABLE_ATTRIBUTE_NAME = 'SecurityAuditIAMRoleArn'
TABLE_NAME = 'cloudformation-stack-emissions'
TABLE_REGION = 'us-west-2'


def get_security_audit_role_arns() -> List[str]:
    """Fetch list ARNs of security auditing IAM Roles

    :return: List of ARNs
    """
    action_args = {
        'TableName': TABLE_NAME,
        'IndexName': TABLE_INDEX_NAME,
        'Select': 'SPECIFIC_ATTRIBUTES',
        'ProjectionExpression': TABLE_ATTRIBUTE_NAME,
        'KeyConditionExpression': '#c = :v',
        'ExpressionAttributeNames': {'#c': TABLE_INDEX_NAME},
        'ExpressionAttributeValues': {':v': {'S': TABLE_CATEGORY}},
    }
    items = get_paginated_results(
        'dynamodb',
        'query',
        'Items',
        {'region_name': TABLE_REGION},
        action_args,
    )
    return [
        x[TABLE_ATTRIBUTE_NAME]['S']
        for x in items
        if TABLE_ATTRIBUTE_NAME in x
    ]
