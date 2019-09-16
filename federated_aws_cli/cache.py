import functools
import jose.exceptions
import json
import logging
import os
import time

from jose import jwt
from stat import S_IRWXG, S_IRWXO, S_IRWXU

# TODO: move to config
CLOCK_SKEW_ALLOWANCE = 500  # 5 minutes
logger = logging.getLogger(__name__)

# the cache directory is the same place we store the config
cache_dir = os.path.join(os.path.expanduser("~"), ".federated_aws_cli")


def __requires_safe_cache_dir(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not safe:
            logger.debug("Cache directory at {} has invalid permissions.".format(cache_dir))
        else:
            return func(*args, **kwargs)

    return wrapper


@__requires_safe_cache_dir
def read_id_token(client_id, key=None):
    logger.debug("in read_id_token")
    path = os.path.join(cache_dir, "id_" + client_id)

    if not os.path.exists(path):
        return None

    mode = os.stat(path).st_mode

    if not mode & S_IRWXG and not mode & S_IRWXO:  # not group/world readable
        try:
            with open(path, "r") as f:
                token = json.load(f)
        except (IOError, PermissionError):
            logger.debug("Unable to read id token from: {}".format(path))
            return None

        # Try to decode the ID token
        try:
            id_token_dict = jwt.decode(
                token=token["id_token"],
                key=key,
                audience=client_id
            )
        except jose.exceptions.JOSEError:
            return None

        if id_token_dict.get('exp') - time.time() > CLOCK_SKEW_ALLOWANCE:
            logger.debug("Successfully read cached id token at: {}".format(path))
            return token
    else:
        logger.error("Error: id token at {} has improper permissions!".format(path))

    return None


@__requires_safe_cache_dir
def write_id_token(client_id, token):
    path = os.path.join(cache_dir, "id_" + client_id)

    try:
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode=0o600), "w") as f:
            if isinstance(token, dict):
                json.dump(token, f, indent=2)
            else:
                f.write(token)

        logger.debug("Successfully wrote token to: {}".format(path))
    except (IOError, PermissionError):
        logger.debug("Unable to write id token to: {}".format(path))


def verify_cache_dir_permissions(path=cache_dir):
    if os.path.exists(path):
        mode = os.stat(path).st_mode

        logger.debug("Cache directory permissions are: {}".format(mode))

        return (
            mode & S_IRWXU == 448   # 7
            and not mode & S_IRWXG  # 0
            and not mode & S_IRWXO  # 0
        )

    return False


safe = verify_cache_dir_permissions()
