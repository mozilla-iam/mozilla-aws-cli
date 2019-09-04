import boto3
from moto import mock_iam, mock_sts
from ..functions.group_role_map_builder import build_group_role_map


@mock_iam
@mock_sts
def test_get_role_group_map():
    assume_role_policy_document_with_conditions = '''
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/example.com/"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "example.com/:aud": "xRFzU2bj7Lrbo3875aXwyxIArdkq1AOT"
        },
        "ForAnyValue:StringLike": {
          "example.com/:amr": "test_group"
        }
      }
    }
  ]
}'''
    assume_role_policy_document = '''
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Principal":{
        "AWS":"arn:aws:iam::123456789012:root"
      },
      "Action":"sts:AssumeRole"
    }
  ]
}'''
    client = boto3.client('iam')
    response = client.create_role(
        RoleName='TestRoleToAssume',
        AssumeRolePolicyDocument=assume_role_policy_document,
        Description='Test role to assume',
    )
    role_to_assume_arn = response['Role']['Arn']
    response = client.create_role(
        RoleName='TestRoleWithFederatedConditions',
        AssumeRolePolicyDocument=assume_role_policy_document_with_conditions,
        Description='Test role with federated conditions',
    )
    groups, aliases = build_group_role_map([role_to_assume_arn])

    assert len(groups) == 0
    assert list(aliases.values()) == [[]]

    response = client.create_account_alias(AccountAlias='account-alias-test')
    groups, aliases = build_group_role_map([role_to_assume_arn])
    assert list(aliases.values()) == [['account-alias-test']]

    # Enable these tests once get_federated_groups_for_policy is written
    # assert 'test_groups' in groups
    # assert len(groups) == 1
    # assert len(groups['test_groups']) == 1

    # TODO : Add a test to confirm that when 2 roles are encountered where one
    # is invalid/unsupported, the other role still gets processed
