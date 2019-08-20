import requests


def get_role_arns(endpoint, token, key, audience):
    headers = {"Content-Type": "application/json"}
    body = {
        "token": token,
        "key": key,
        "audience": audience
    }
    r = requests.post(endpoint, headers=headers, json=body)
    return r.json()
