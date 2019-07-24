import boto3


def get_paginated_results(product, action, key, credentials=None, args=None):
    """Paginate through AWS API responses, combining them into a list

    :param str product: AWS product name
    :param str action: AWS API action name
    :param str key: The parent key in the paginated response
    :param dict credentials: Optional AWS API credentials
    :param dict args: Optional additional arguments to pass to action method
    :return: list of responses from all pages
    """

    args = {} if args is None else args
    credentials = {} if credentials is None else credentials
    return [y for sublist in [x[key] for x in boto3.client(
        product, **credentials).get_paginator(action).paginate(**args)]
            for y in sublist]


def flip_map(arn_group_map):
    """Flip the map of ARN to group list to group to ARN list

    :param dict arn_group_map: ARN to group list map
    :return: Group to ARN list map
    """
    group_arn_map = {}
    for arn in arn_group_map:
        for group in arn_group_map[arn]:
            if group not in group_arn_map:
                group_arn_map[group] = []
            group_arn_map[group].append(arn)
    return group_arn_map


def get_federated_groups_for_policy(policy_document):
    # Stub until this function is developed
    return []


def get_group_role_map(assumed_role_arns):
    """Build map of IAM roles to the OIDC claimed groups relevant in those roles' assumption policies.

    Given a list of IAM Role ARNs to assume, iterate over those roles,
    assuming each of them. Acting as each of these assumed roles, query for all
    IAM roles in that AWS account, passing each role's AssumeRolePolicyDocument
    to get_federated_groups_for_policy to fetch a list of OIDC claim groups
    in that policy document. Return a map that looks like

    {
        'team_bar': [
            'arn:aws:iam::123456789012:role/role-for-anyone-but-team-bar',
            'arn:aws:iam::123456789012:role/project-baz-role'
        ],
        'team_foo': [
            'arn:aws:iam::123456789012:role/role-for-team-foo',
            'arn:aws:iam::123456789012:role/project-baz-role']
    }

    :param list assumed_role_arns: list of IAM role ARN strings
    :return: map of IAM ARNs to related OIDC claimed group names
    """
    assumed_role_credentials = {}
    role_group_map = {}
    for assumed_role_arn in assumed_role_arns:
        aws_account_id = assumed_role_arn.split(':')[4]
        client_sts = boto3.client('sts')
        response = client_sts.assume_role(
            RoleArn=assumed_role_arn,
            RoleSessionName='Federated-Login-Policy-Collector')
        assumed_role_credentials[aws_account_id] = {
            'aws_access_key_id': response['Credentials']['AccessKeyId'],
            'aws_secret_access_key': response['Credentials']['SecretAccessKey'],
            'aws_session_token': response['Credentials']['SessionToken']}
        roles = get_paginated_results(
            'iam', 'list_roles', 'Roles', assumed_role_credentials[aws_account_id])
        for role in roles:
            groups = []
            groups.extend(get_federated_groups_for_policy(
                role['AssumeRolePolicyDocument']))
            role_group_map[role['Arn']] = groups
    return flip_map(role_group_map)
