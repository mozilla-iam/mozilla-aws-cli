import yaml


def parse_config(file_location):
    try:
        with open(file_location, 'r') as stream:
            return yaml.load(stream)
    except:
        return {}
