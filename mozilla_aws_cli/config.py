import appdirs
import logging
import os.path
import sys


logger = logging.getLogger(__name__)

CONFIG_FILE_NAME = "config.ini"
IS_MACOS = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"
NAME = "Mozilla AWS CLI"
SHORT_NAME = "maws"

if IS_WINDOWS:
    CACHE_DIR = appdirs.user_cache_dir(NAME, "")
    CONFIG_DIR = appdirs.user_config_dir(NAME, "", roaming=True)

    CONFIG_PATHS = [
        os.path.join(appdirs.site_config_dir(NAME, ""), CONFIG_FILE_NAME),
        os.path.join(CONFIG_DIR, CONFIG_FILE_NAME),
    ]
elif IS_MACOS:
    # as this is a CLI app, this forces the app to use the XDG specification
    # instead of storing its configuration in ~/Library/Application Support
    appdirs.system = "linux2"

    CACHE_DIR = appdirs.user_cache_dir(SHORT_NAME)
    CONFIG_DIR = appdirs.user_config_dir(SHORT_NAME)

    CONFIG_PATHS = [
        os.path.join("/etc", SHORT_NAME, CONFIG_FILE_NAME),  # no XDG in /etc
        os.path.join(CONFIG_DIR, CONFIG_FILE_NAME),
    ]
else:
    CACHE_DIR = appdirs.user_cache_dir(SHORT_NAME)
    CONFIG_DIR = appdirs.user_config_dir(SHORT_NAME)

    CONFIG_PATHS = [
        os.path.join(appdirs.site_config_dir(SHORT_NAME), CONFIG_FILE_NAME),
        os.path.join(CONFIG_DIR, CONFIG_FILE_NAME),
    ]
