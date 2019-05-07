import yaml
import logging

logger = logging.getLogger(__name__)


def parse_config(file_location):
    try:
        with open(file_location, "r") as stream:
            return yaml.load(stream, Loader=yaml.SafeLoader)
    except Exception as e:
        logger.error("Could not open configuration file {}: {}".format(
            file_location, e))
        return {}
