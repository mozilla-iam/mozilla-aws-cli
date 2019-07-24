import sys
sys.path.append('..')

import boto3
from moto import mock_iam, mock_sts
from get_group_role_map import get_group_role_map

@mock_iam
@mock_sts
def test_get_role_group_map():
    test_assume_role_policy_document_with_federated_conditions = '''
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/auth-dev.mozilla.auth0.com/"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "auth-dev.mozilla.auth0.com/:aud": "xRFzU2bj7Lrbo3875aXwyxIArdkq1AOT"
        },
        "ForAnyValue:StringLike": {
          "auth-dev.mozilla.auth0.com/:amr": "test_group"
        }
      }
    }
  ]
}'''
    client = boto3.client('iam')
    response = client.create_role(
        RoleName='TestRoleToAssume',
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}',
        Description='Test role to assume')
    role_to_assume_arn = response['Role']['Arn']
    response = client.create_role(
        RoleName='TestRoleWithFederatedConditions',
        AssumeRolePolicyDocument=test_assume_role_policy_document_with_federated_conditions,
        Description='Test role with federated conditions')
    groups = get_group_role_map([role_to_assume_arn])

    assert len(groups) == 0

    # Enable these tests once get_federated_groups_for_policy is written
    # assert 'test_groups' in groups
    # assert len(groups) == 1
    # assert len(groups['test_groups']) == 1


if __name__ == '__main__':
    test_get_role_group_map()
