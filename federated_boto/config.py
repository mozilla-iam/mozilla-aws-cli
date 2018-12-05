import yaml


def parse_config(file_location):
    with open(file_location, 'r') as stream:
        return yaml.load(stream)
