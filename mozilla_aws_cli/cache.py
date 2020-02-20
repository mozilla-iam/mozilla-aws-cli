import datetime
import functools
import jose.exceptions
import json
import logging
import os
import sys
import time
import subprocess

from collections import OrderedDict
from contextlib import contextmanager
from future.utils import viewitems
from hashlib import sha256
from jose import jwt
from stat import S_IRWXG, S_IRWXO, S_IRWXU

from .config import CONFIG_DIR, CACHE_DIR, IS_WINDOWS

if sys.version_info[0] >= 3:
    import configparser
else:
    import ConfigParser as configparser

ZERO = datetime.timedelta(0)


class UTC(datetime.tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


utc = UTC()

if sys.version_info[0] >= 3:
    def timestamp(dt):
        return dt.timestamp()
else:
    def timestamp(dt):
        epoch = datetime.datetime.utcfromtimestamp(0).replace(tzinfo=utc)
        return (dt - epoch).total_seconds()

# TODO: move to config
CLOCK_SKEW_ALLOWANCE = 300  # 5 minutes
UNDOCUMENTED_AWS_LIMIT_MAX_ID_TOKEN_AGE = 86400  # 1 day
GROUP_ROLE_MAP_CACHE_TIME = 3600  # 1 hour
CREDENTIALS_TO_AWS_MAP = {
    "AccessKeyId": "aws_access_key_id",
    "SecretAccessKey": "aws_secret_access_key",
    "SessionToken": "aws_session_token",
}

logger = logging.getLogger(__name__)

# the cache directory is the same place we store the config
caching = True


def _fix_permissions(path, permissions):
    # Windows uses %APPDATA%, which is presumed to be secure
    if IS_WINDOWS:
        return True

    try:
        os.chmod(path, permissions)
        logger.debug("Successfully repaired permissions on: {}".format(path))
        return True
    except OSError:
        logger.debug("Failed to repair permissions on: {}".format(path))
        return False


def _readable_by_others(path, fix=True):
    # Windows uses %APPDATA%, which is presumed to be secure
    if IS_WINDOWS:
        return False

    mode = os.stat(path).st_mode
    readable_by_others = mode & S_IRWXG or mode & S_IRWXO

    if readable_by_others and fix:
        logger.debug(
            "Cached file at {} has invalid permissions of {}. Attempting to "
            "fix.".format(path, mode))

        readable_by_others = not _fix_permissions(path, 0o600)

    return readable_by_others


def _requires_caching(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if caching:
            return func(*args, **kwargs)
        else:
            logger.debug("Caching reads disabled on {}.".format(CACHE_DIR))

    return wrapper


def _requires_safe_cache_dir(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not safe:
            if os.path.exists(CACHE_DIR):
                mode = os.stat(CACHE_DIR).st_mode
                logger.debug("Cache directory at {} has invalid permissions "
                             "of {}.".format(CACHE_DIR, mode))
            else:
                logger.debug(
                    "Cache directory {} doesn't exist".format(CACHE_DIR))
        else:
            return func(*args, **kwargs)

    return wrapper


@contextmanager
def _safe_write(path):
    # Try to open the file as 600
    f = os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w")
    yield f
    f.close()


def disable_caching():
    logger.debug("Global cache reading disabled.")
    globals()["caching"] = False


@_requires_safe_cache_dir
def write_aws_cli_credentials(profile, credentials):
    # We call aws a bunch of times, getting all the return values
    retval = 0

    # Update the values
    for cred_key, aws_key in viewitems(CREDENTIALS_TO_AWS_MAP):
        if cred_key in credentials:
            process = ["aws", "configure", "set",
                       aws_key, credentials[cred_key]]

            if profile != "default":
                process += ["--profile", profile]

            _retval = subprocess.call(process)
            retval = retval | _retval

            logger.debug("`{}` executed with return code: {}".format(
                " ".join(process),
                _retval
            ))

    return None if retval else True


@_requires_safe_cache_dir
def read_aws_shared_credentials():
    """
    :return: A ConfigParser object
    """
    # Create a sha256 of the endpoint url, so fix length and remove weird chars
    path = os.path.join(CONFIG_DIR, "credentials")

    # we can preserve comments with Python 3
    if sys.version_info[0] < 3:
        config = configparser.ConfigParser()
    else:
        config = configparser.ConfigParser(allow_no_value=True,
                                           comment_prefixes=())

    if not os.path.exists(path) or _readable_by_others(path):
        logger.debug(
            "There is no credentials file at {} or it exists but is readable "
            "by others. We won't use it".format(path))
        return config

    logger.debug("Trying to read credentials file at: {}".format(path))

    try:
        with open(path, "r") as f:
            if sys.version_info >= (3, 2):
                config.read_file(f)
            else:
                config.readfp(f)
    except (IOError, OSError):
        logger.debug("Unable to read credentials file from: {}".format(path))

    return config


@_requires_safe_cache_dir
def write_aws_shared_credentials(profile, credentials):
    path = os.path.join(CONFIG_DIR, "credentials")

    # Try to read in the existing credentials
    config = read_aws_shared_credentials()

    # Add all the new credentials to the config object
    if not config.has_section(profile):
        config.add_section(profile)
        logger.debug("Added new profile: {}".format(profile))

    # Update the values
    for cred_key, aws_key in viewitems(CREDENTIALS_TO_AWS_MAP):
        if cred_key in credentials:
            config.set(profile, aws_key, credentials[cred_key])

    # Order all the sections alphabetically
    config._sections = OrderedDict(
        sorted(viewitems(config._sections), key=lambda t: t[0])
    )

    try:
        with _safe_write(path) as f:
            config.write(f)

            logger.debug(
                "Successfully wrote AWS shared credentials credentials to: "
                "{}".format(path))

            return path
    except (IOError, OSError):
        logger.error(
            "Unable to write AWS shared credentials to: {}".format(path))

        return None


@_requires_caching
@_requires_safe_cache_dir
def read_group_role_map(url):
    # Create a sha256 of the endpoint url, so fix length and remove weird chars
    path = os.path.join(
        CACHE_DIR, "rolemap_" + sha256(url.encode("utf-8")).hexdigest())

    if not os.path.exists(path) or _readable_by_others(path):
        logger.debug(
            "There is no role map file at {} or it exists but is readable "
            "by others. We won't use it".format(path))
        return None

    if time.time() - os.path.getmtime(path) > GROUP_ROLE_MAP_CACHE_TIME:
        # expired
        return None
    else:
        logger.debug("Using cached role map for {} at: {}".format(url, path))

        try:
            with open(path, "r") as f:
                return json.load(f)
        except (IOError, OSError):
            logger.debug("Unable to read role map from: {}".format(path))
            return None


@_requires_safe_cache_dir
def write_group_role_map(url, role_map):
    # Create a sha256 of the endpoint url, so fix length and remove weird chars
    url = sha256(url.encode("utf-8")).hexdigest()

    path = os.path.join(CACHE_DIR, "rolemap_" + url)

    try:
        with _safe_write(path) as f:
            json.dump(role_map, f, indent=2)
            f.write("\n")

            logger.debug("Successfully wrote role map to: {}".format(path))
    except (IOError, OSError):
        logger.debug("Unable to write role map to: {}".format(path))


@_requires_caching
@_requires_safe_cache_dir
def read_id_token(issuer, client_id, key=None):
    if issuer is None or client_id is None:
        return None

    # Create a sha256 of the issuer url, so fix length and remove weird chars
    issuer = sha256(issuer.encode("utf-8")).hexdigest()

    path = os.path.join(CACHE_DIR, "id_" + issuer + "_" + client_id)

    if not os.path.exists(path) or _readable_by_others(path):
        logger.debug(
            "There is no ID token file at {} or it exists but is readable "
            "by others. We won't use it".format(path))
        return None

    try:
        with open(path, "r") as f:
            token = json.load(f)
    except (IOError, OSError):
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

    if (id_token_dict.get("exp") - time.time() > CLOCK_SKEW_ALLOWANCE
            and time.time() - id_token_dict.get("iat") < UNDOCUMENTED_AWS_LIMIT_MAX_ID_TOKEN_AGE):
        logger.debug("Successfully read cached id token at: {}".format(path))
        return token
    else:
        logger.debug("Cached id token has expired: {}".format(path))
        return None


@_requires_safe_cache_dir
def write_id_token(issuer, client_id, token):
    if issuer is None or client_id is None:
        return None

    # Create a sha256 of the issuer url, so fix length and remove weird chars
    path = os.path.join(
        CACHE_DIR,
        "id_" + sha256(issuer.encode("utf-8")).hexdigest() + "_" + client_id)

    try:
        with _safe_write(path) as f:
            if isinstance(token, dict):
                json.dump(token, f, indent=2)
                f.write("\n")
            else:
                f.write(token)

            logger.debug("Successfully wrote token to: {}".format(path))
    except (IOError, OSError):
        logger.debug("Unable to write id token to: {}".format(path))


@_requires_caching
@_requires_safe_cache_dir
def read_sts_credentials(role_arn):
    if role_arn is None:
        return None
    else:
        # Create a sha256 of the role arn, so fix length and remove weird chars
        path = os.path.join(
            CACHE_DIR, "stscreds_" + sha256(
                role_arn.encode("utf-8")).hexdigest())

    if not os.path.exists(path) or _readable_by_others(path):
        logger.debug(
            "There is no STS credential file at {} or it exists but is "
            "readable by others. We won't use it".format(path))
        return None

    try:
        with open(path, "r") as f:
            sts = json.load(f)

            exp = datetime.datetime.strptime(
                sts["Expiration"],
                "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=utc)
            logger.debug(
                "Cached STS credentials expire at {} or {} seconds compared "
                "to the current time of {}. expiry - current time = {}".format(
                    exp,
                    timestamp(exp),
                    time.time(),
                    timestamp(exp) - time.time()))
            if timestamp(exp) - time.time() > CLOCK_SKEW_ALLOWANCE:
                logger.debug(
                    "Using STS credentials at: {} expiring in: {}".format(
                        path, timestamp(exp) - time.time()))
                return sts
            else:
                logger.debug(
                    "Cached STS credentials have expired.".format(path))
                return None
    except (IOError, OSError):
        logger.debug("Unable to read STS credentials from: {}".format(path))
        return None


@_requires_safe_cache_dir
def write_sts_credentials(role_arn, sts_creds):
    # Create a sha256 of the role arn, so fix length and remove weird chars
    path = os.path.join(
        CACHE_DIR, "stscreds_" + sha256(role_arn.encode("utf-8")).hexdigest())

    try:
        with _safe_write(path) as f:
            json.dump(sts_creds, f, indent=2)
            f.write("\n")

            logger.debug(
                "Successfully wrote STS credentials to: {}".format(path))
    except (IOError, OSError):
        logger.debug("Unable to write STS credentials to: {}".format(path))


def verify_dir_permissions(path=CONFIG_DIR):
    # Windows uses %APPDATA%, which is presumed to be secure
    if os.path.exists(path) and IS_WINDOWS:
        return True
    elif os.path.exists(path):
        mode = os.stat(path).st_mode
        logger.debug("Directory permissions on {} are: {}".format(path, mode))
        if (
            mode & S_IRWXU == 448   # 7
            and not mode & S_IRWXG  # 0
            and not mode & S_IRWXO  # 0
        ):
            # Directory exists and permissions are correct
            return True
    else:
        # Attempt to create the directory with the right permissions, if it
        # doesn't exist
        try:
            os.makedirs(path)
        except (IOError, OSError):
            logger.debug("Unable to create directory: {}".format(path))
            return False

    return _fix_permissions(path, 0o700)


# First let's see if the directories have the right permissions
safe = verify_dir_permissions(CONFIG_DIR) and verify_dir_permissions(CACHE_DIR)
