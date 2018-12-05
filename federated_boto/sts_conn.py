import requests
from jwt import (
    JWT,
    jwk_from_dict,
    jwk_from_pem,
)


# https://sts.amazonaws.com
# https://sts.amazonaws.com/?Action=GetFederationToken&Name=Megan&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIXXXXXXXXXXWIQ%2F20130424%2Fus-east-1%2Fsts%2Faws4_request&X-Amz-Date=20130424T183200Z&X-Amz-SignedHeaders=host%3Bx-amz-date&X-Amz-Signature=db754013466768c11a86a610796faad6a041bcad9d83f4c958cac82988d2f7d7
# GetSessionToken


# AssumeRoleWithWebIdentity

def deserialize_bearer_token(bearer_token, public_key):
    """ accepts a bearer token and reaches out to
        sts to get a temporary session and access key
    """
    # jwt formated bearer token
    #
    # verify format of jwt bearer token

    jwt = JWT()
    return jwt.decode(bearer_token, public_key)


def retrieve_access_keys(bearer_token, public_key):
    # {
    #   "access_token": "eyJz93a...k4laUWw",
    #   "refresh_token": "GEbRxBN...edjnXbL",
    #   "id_token": "eyJ0XAi...4faeEoQ",
    #   "token_type": "Bearer"
    # }

    # use access token from deserialized bearer token to sts endpoint
    bearer_dict = deserialize_bearer_token(bearer_token, public_key)

    # role_arn = ''
    # role_session_name = ''
    # provider_id = ''
    # duration_seconds = 123
    # # some real basic verification on bearer token
    # sts_url = "https://sts.amazonaws.com/"
    # parameters = {
    #     'Action': 'AssumeRoleWithWebIdentity'
    #     'RoleArn': role_arn,
    #     'RoleSessionName': role_session_name,
    #     'WebIdentityToken': bearer_dict['access_token']
    #     'ProviderId': provider_id,
    #     # 'WebIdentityToken': ''
    #     # Version=2011-06-15
    # }

    # RoleArn='string',
    # RoleSessionName='string',
    # WebIdentityToken='string',
    # ProviderId='string',
    # DurationSeconds=123

    # sending get request and saving the response as response object
    # resp = requests.get(url=sts_url, params=parameters)
    # import pdb; pdb.set_trace()
    pass

# req.body = {
#   client_id: client,
#   grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
#   id_token: JSON.parse(res.body)['id_token'],
#   scope: 'openid', api_type: 'aws'
# }.to_json
