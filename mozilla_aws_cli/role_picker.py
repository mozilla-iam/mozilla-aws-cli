import logging
import platform
import requests

from .cache import read_group_role_map, write_group_role_map


logger = logging.getLogger(__name__)

ENV_VARIABLE_NAME_MAP = {
    "AccessKeyId": "AWS_ACCESS_KEY_ID",
    "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
    "SessionToken": "AWS_SESSION_TOKEN",
}


def get_aws_env_variables(credentials):
    result = ""
    verb = "set" if platform.system() == "Windows" else "export"
    for key in [x for x in credentials if x in ENV_VARIABLE_NAME_MAP]:
        result += "{} {}={}\n".format(
            verb, ENV_VARIABLE_NAME_MAP[key], credentials[key])
    return result


def get_roles_and_aliases(endpoint, token, key):
    role_map = read_group_role_map(endpoint)

    if role_map is None:
        logging.debug("Getting roles and aliases from: {}".format(endpoint))
        headers = {"Content-Type": "application/json"}
        body = {
            "token": token,
            "key": key,
        }

        role_map = requests.post(endpoint, headers=headers, json=body).json()

        if "error" in role_map:
            logging.error(
                "Unable to retrieve rolemap: {}".format(role_map["error"]))
            return None
        else:
            write_group_role_map(endpoint, role_map)

    return role_map
