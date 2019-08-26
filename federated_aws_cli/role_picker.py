from collections import defaultdict
import logging
import platform
import requests
import consolemenu
import consolemenu.menu_component
try:
    # Python 3.3+
    from shutil import get_terminal_size
except ImportError:
    # Python 3.3-
    from backports.shutil_get_terminal_size import get_terminal_size

logger = logging.getLogger(__name__)

ENV_VARIABLE_NAME_MAP = {
    "AccessKeyId": "AWS_ACCESS_KEY_ID",
    "SecretAccessKey": "AWS_SECRET_ACCESS_KEY",
    "SessionToken": "AWS_SESSION_TOKEN",
}
SCREEN_WIDTH, SCREEN_HEIGHT = get_terminal_size((80, 40))


def get_aws_env_variables(credentials):
    result = ""
    verb = "set" if platform.system() == "Windows" else "export"
    for key in [x for x in credentials if x in ENV_VARIABLE_NAME_MAP]:
        result += "{} {}={}\n".format(
            verb, ENV_VARIABLE_NAME_MAP[key], credentials[key])
    return result


def get_roles_and_aliases(endpoint, token, key):
    logging.debug("Getting roles and aliases from: {}".format(endpoint))
    headers = {"Content-Type": "application/json"}
    body = {
        "token": token,
        "key": key,
    }
    r = requests.post(endpoint, headers=headers, json=body)
    return r.json()


def show_menu(menu_selections, role_arns):
    """Display a set of menu selections and return the associated role_arn
    once the user selects a role

    :param list menu_selections: A list of menu selections to display
    :param list role_arns: A list of IAM Role ARNs
    :return: The IAM Role ARN selected
    """
    screen = consolemenu.Screen()
    formatter = consolemenu.MenuFormatBuilder(
        consolemenu.menu_component.Dimension(
            width=SCREEN_WIDTH,
            height=SCREEN_HEIGHT))

    menu = consolemenu.ConsoleMenu(
        title="Select which AWS account and IAM role you'd like to assume",
        subtitle="Account Alias (Account ID) : Role Name",
        screen=screen,
        formatter=formatter
    )
    for i in range(len(menu_selections)):
        menu.append_item(consolemenu.items.SelectionItem(menu_selections[i], i))
    menu.show()
    return (role_arns[menu.selected_option]
            if menu.selected_option != len(menu_selections) else None)


def show_role_picker(roles_and_aliases):
    """Display an IAM Role picker menu and return the role picked by the user

    :param dict roles_and_aliases: A dict with two keys, 'roles' and 'aliases'
        {
            'roles': [
                'arn:aws:iam::123456789012:role/role-mariana',
                'arn:aws:iam::234567890123:role/different/path/to/blackburn',
            ],
            'aliases': {
                '123456789012': ['Trenches-Account'],
                '234567890123': ['Mountains-Account'],
            }
        }
    :return: The IAM Role ARN that was selected by the user
    """
    role_arns = roles_and_aliases.get('roles', [])
    alias_map = roles_and_aliases.get('aliases', {})
    alias_to_id = {aliases[0]: account_id
                   for account_id, aliases in alias_map.items()}
    options = defaultdict(dict)
    for role_arn in role_arns:
        account_id = role_arn.split(':')[4]
        # Get the account alias or just use the account ID if there's no alias
        account_alias = alias_map.get(account_id, [account_id])[0]
        # TODO : Allow for a "hints" file which sets aliases for accounts if
        # they have no alias set
        role_name = role_arn.split(':')[5].split('/')[-1]
        options[account_alias][role_name] = role_arn

    # This assumes that account aliases are globally unique and live within a
    # single common global namespace
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html#AboutAccountAlias
    menu_selections = []
    role_arns = []
    for account_alias in sorted(options.keys()):
        for role_name in sorted(options[account_alias].keys()):
            menu_selections.append('{} ({}) : {}'.format(
                account_alias, alias_to_id[account_alias], role_name))
            role_arns.append(options[account_alias][role_name])
    result = show_menu(menu_selections, role_arns)
    return result
