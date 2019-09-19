import functools
import jose.exceptions
import json
import logging
import os
import sys
import time

from contextlib import contextmanager
from hashlib import sha256
from jose import jwt
from stat import S_IRWXG, S_IRWXO, S_IRWXU


# TODO: move to config
CLOCK_SKEW_ALLOWANCE = 300         # 5 minutes
GROUP_ROLE_MAP_CACHE_TIME = 3600   # 1 hour

if sys.version_info < (3, 3):
    class PermissionError(OSError):
        pass

logger = logging.getLogger(__name__)

# the cache directory is the same place we store the config
cache_dir = os.path.join(os.path.expanduser("~"), ".federated_aws_cli")


def _fix_permissions(path, permissions):
    try:
        os.chmod(path, permissions)
        logger.debug("Successfully repaired permissions on: {}".format(path))
        return True
    except (IOError, PermissionError, OSError):
        logger.debug("Failed to repair permissions on: {}".format(path))
        return False


def _readable_by_others(path, fix=True):
    mode = os.stat(path).st_mode
    readable_by_others = mode & S_IRWXG or mode & S_IRWXO

    if readable_by_others and fix:
        logger.debug("Cached file at {} has invalid permissions. Attempting to fix.".format(path))

        readable_by_others = not _fix_permissions(path, 0o600)

    return readable_by_others


def _requires_safe_cache_dir(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not safe:
            logger.debug("Cache directory at {} has invalid permissions.".format(cache_dir))
        else:
            return func(*args, **kwargs)

    return wrapper


@contextmanager
def _safe_write(path):
    # Try to open the file as 600
    f = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode=0o600), "w")
    yield f
    f.close()


@_requires_safe_cache_dir
def read_group_role_map(url):
    # Create a sha256 of the endpoint url, so fix length and remove weird chars
    path = os.path.join(cache_dir, "rolemap_" + sha256(url.encode("utf-8")).hexdigest())

    if not os.path.exists(path) or _readable_by_others(path):
        return None

    if time.time() - os.path.getmtime(path) > GROUP_ROLE_MAP_CACHE_TIME:  # expired
        return None
    else:
        logger.debug("Using cached role map at: {}".format(path))

        try:
            with open(path, "r") as f:
                return json.load(f)
        except (IOError, PermissionError):
            logger.debug("Unable to read role map from: {}".format(path))
            return None


@_requires_safe_cache_dir
def write_group_role_map(url, role_map):
    # Create a sha256 of the endpoint url, so fix length and remove weird chars
    url = sha256(url.encode("utf-8")).hexdigest()

    path = os.path.join(cache_dir, "rolemap_" + url)

    try:
        with _safe_write(path) as f:
            json.dump(role_map, f, indent=2)

            logger.debug("Successfully wrote role map to: {}".format(path))
    except (IOError, PermissionError):
        logger.debug("Unable to write role map to: {}".format(path))


@_requires_safe_cache_dir
def read_id_token(issuer, client_id, key=None):
    if issuer is None or client_id is None:
        return None

    # Create a sha256 of the issuer url, so fix length and remove weird chars
    issuer = sha256(issuer.encode("utf-8")).hexdigest()

    path = os.path.join(cache_dir, "id_" + issuer + "_" + client_id)

    if not os.path.exists(path) or _readable_by_others(path):
        return None

    if not _readable_by_others(path):
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
            logger.debug("Cached id token has expired: {}".format(path))
            return None
    else:
        logger.error("Error: id token at {} has improper permissions!".format(path))


@_requires_safe_cache_dir
def write_id_token(issuer, client_id, token):
    if issuer is None or client_id is None:
        return None

    # Create a sha256 of the issuer url, so fix length and remove weird chars
    issuer = sha256(issuer.encode("utf-8")).hexdigest()

    path = os.path.join(cache_dir, "id_" + issuer + "_" + client_id)

    try:
        with _safe_write(path) as f:
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
