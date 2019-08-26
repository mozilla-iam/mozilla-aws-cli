import json
import yaml

try:
    input = raw_input
except NameError:
    pass

FORMAT_PROMPT = '''Policy format options :
* c/cloudformation : A YAML CloudFormation template which provisions a federated IAM role
* j/json-cloudformation : A JSON CloudFormation template which provisions a federated IAM role
* a/awscli : An AWS CLI command line command which creates a federated IAM role
* p/policy : The JSON trust relationship portion of the IAM policy (this can be copy pasted into the web console)'''

GROUPS_PROMPT = '''User groups can be granted access to the federated IAM role.
* Supported : Allow users in the group foo to assume the IAM role : "foo"
* Supported : Allow users in the group foo as well as users in the group bar to assume the IAM role : "foo,bar"
* Supported : Allow users in any group that begins with "foo_" : "foo_*"'''


def get_json(o):
    return json.dumps(o, indent=4, sort_keys=True)


def get_yaml(o):
    return yaml.safe_dump(o, default_flow_style=False)


def create_cloudformation_template(groups, formatter):
    identity_provider = 'arn:aws:iam::656532927350:oidc-provider/auth-dev.mozilla.auth0.com/'
    audience_key = 'auth-dev.mozilla.auth0.com/:aud'
    audience_value = 'xRFzU2bj7Lrbo3875aXwyxIArdkq1AOT'
    amr_key = 'auth-dev.mozilla.auth0.com/:amr'
    resource_name = 'MyFederatedIAMRole'
    verb='StringLike' if any('*' in x or '?' in x for x in groups) else 'StringEquals'
    template = {
        'AWSTemplateFormatVersion': '2010-09-09',
        'Resources': {
            resource_name: {
                'Type': 'AWS::IAM::Role',
                'Properties': {
                    'AssumeRolePolicyDocument': {
                        'Version': '2012-10-17',
                        'Statement': [
                            {
                                'Effect': 'Allow',
                                'Principal': {
                                    'Federated': identity_provider
                                },
                                'Action': 'sts:AssumeRole',
                                'Condition': {
                                    'StringEquals': {
                                        audience_key: audience_value
                                    },
                                    'ForAnyValue:{}'.format(verb): {

                                    }
                                }
                            }
                        ]
                    },
                    'Policies': [
                        {
                            'PolicyName': 'ExamplePolicyGrantingGetCallerIdentity',
                            'PolicyDocument': {
                                'Version': '2012-10-17',
                                'Statement': [
                                    {
                                        'Effect': 'Allow',
                                        'Action': [
                                            'sts:GetCallerIdentity'
                                        ],
                                        'Resource': '*'
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        }
    }
    template['Resources'][resource_name]['Properties']['AssumeRolePolicyDocument']['Statement'][0]['Condition']['ForAnyValue:{}'.format(verb)][amr_key] = groups
    return formatter(template)


def create_awscli_command(groups):
    return ''


def create_policy_json(groups):
    return ''


def main():
    format = None
    groups = []
    print(FORMAT_PROMPT + "\n")
    while format is None or format[0] not in 'cjap':
        format = input('What format would you like the policy returned in? (c/cloudformation / a/awscli / j/json) ').lower()
        if len(format) == 0:
            exit(0)
    print(GROUPS_PROMPT)
    while len(groups) == 0:
        groups = [x for x in input('What groups would you like to grant access to this role? ').split(',') if x != '']

    print("\n\n")
    if format[0] == 'c':
        print(create_cloudformation_template(groups, get_yaml))
    elif format[0] == 'j':
            print(create_cloudformation_template(groups, get_json))
    elif format[0] == 'a':
        print(create_awscli_command(groups))
    elif format[0] == 'p':
        print(create_policy_json(groups))


if __name__ == "__main__":
    main()
