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
    # C:\Users\<user>\AppData\Local\Mozilla AWS CLI\Cache
    CACHE_DIR = appdirs.user_cache_dir(NAME, "")
    # C:\Users\<user>\AppData\Roaming\Mozilla AWS CLI
    CONFIG_DIR = appdirs.user_config_dir(NAME, "", roaming=True)

    CONFIG_PATHS = [
        # C:\ProgramData\Mozilla AWS CLI\config.ini
        os.path.join(appdirs.site_config_dir(NAME, ""), CONFIG_FILE_NAME),
        # C:\Users\<user>\AppData\Roaming\Mozilla AWS CLI\config.ini
        os.path.join(CONFIG_DIR, CONFIG_FILE_NAME),
    ]
elif IS_MACOS:
    # as this is a CLI app, this forces the app to use the XDG specification
    # instead of storing its configuration in ~/Library/Application Support
    appdirs.system = "linux2"

    CACHE_DIR = appdirs.user_cache_dir(SHORT_NAME)
    # /Users/<user>/.cache/maws
    CONFIG_DIR = appdirs.user_config_dir(SHORT_NAME)
    # /Users/<user>/.config/maws

    CONFIG_PATHS = [
        # /etc/maws/config.ini
        os.path.join("/etc", SHORT_NAME, CONFIG_FILE_NAME),  # no XDG in /etc
        # /Users/<user>/.config/maws/config.ini
        os.path.join(CONFIG_DIR, CONFIG_FILE_NAME),
    ]
else:
    # /home/<user>/.cache/maws
    CACHE_DIR = appdirs.user_cache_dir(SHORT_NAME)
    # /home/<user>/.config/maws
    CONFIG_DIR = appdirs.user_config_dir(SHORT_NAME)

    CONFIG_PATHS = [
        # /etc/xdg/xdg-ubuntu/maws/config.ini  (for Ubuntu)
        os.path.join(appdirs.site_config_dir(SHORT_NAME), CONFIG_FILE_NAME),
        # /home/<user>/.config/maws/config.ini
        os.path.join(CONFIG_DIR, CONFIG_FILE_NAME),
    ]
