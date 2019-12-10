import logging
import os


logger = logging.getLogger(__name__)

IS_WINDOWS = os.name == "nt"
NAME = "Mozilla AWS CLI"

if IS_WINDOWS:
    DOT_DIR = cache_dir = os.path.join(os.path.expandvars("%APPDATA%"), NAME)

    CONFIG_PATHS = [
        os.path.join(os.path.expandvars("%PROGRAMDATA%"), NAME, "config"),
        os.path.join(DOT_DIR, "config"),
    ]
else:
    DOT_DIR = cache_dir = os.path.join(os.path.expanduser("~"), ".maws")

    CONFIG_PATHS = [
        os.path.join("/etc", "maws", "config"),
        os.path.join(DOT_DIR, "config"),
    ]
