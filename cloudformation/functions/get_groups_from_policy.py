from json import loads
from json.decoder import JSONDecodeError


INVALID_OPERATORS = (
    "StringNotEquals", "ForAnyValue:StringNotEquals",
    "StringNotLike", "ForAnyValue:StringNotLike"
)
UNGLOBBABLE_OPERATORS = ("StringEquals", "ForAnyValue:StringEquals")
VALID_OPERATORS = (
    "StringEquals", "ForAnyValue:StringEquals",
    "StringLike", "ForAnyValue:StringLike",
)

VALID_AMRS = (
    "auth-dev.mozilla.auth0.com/:amr",
    "auth.mozilla.auth0.com/:amr",
)
VALID_FEDERATED_PRINCIPAL_KEYS = (
    "arn:aws:iam::656532927350:oidc-provider/auth-dev.mozilla.auth0.com/",
    "arn:aws:iam::371522382791:oidc-provider/auth.mozilla.auth0.com/",
)


def get_groups_from_policy(policy) -> list:
    # groups will be stored as a set to prevent duplicates and then return
    # a list when everything is finished
    policy_groups = set()

    # be flexible on being passed a dictionary (parsed policy) or a string
    # (unparsed policy)
    if isinstance(policy, str):
        try:
            policy = loads(policy)
        except JSONDecodeError:
            return []

    if not isinstance(policy, dict):
        raise ValueError

    # If policy lacks a statement, we can bail out
    if 'Statement' not in policy:
        return []

    for statement in policy["Statement"]:
        if (statement.get("Effect") != "Allow" or
                statement.get("Action") != "sts:AssumeRoleWithWebIdentity" or
                statement.get('Principal', {}).get('Federated') not in
                VALID_FEDERATED_PRINCIPAL_KEYS):
            continue

        operator_count = 0
        for operator in statement.get("Condition", {}).keys():
            # StringNotLike, etc. are not supported
            if operator in INVALID_OPERATORS:
                return []
            # Is a valid operator and contains a valid :amr entry
            elif (operator in VALID_OPERATORS and
                    any(amr in VALID_AMRS for amr in
                        statement["Condition"][operator].keys())):
                operator_count += 1

        # Multiple operators are not supported
        if operator_count != 1:
            return []

        # For clarity:
        # operator --> StringEquals, ForAnyValue:StringLike
        # conditions --> dictionary mapping, e.g. StringEquals: {}
        # condition: auth-dev.mozilla.auth0.com/:amr
        operator_count = 0
        for operator, conditions in statement.get("Condition", {}).items():
            for condition in conditions:
                if condition in VALID_AMRS:
                    groups = conditions[condition]
                    groups = [groups] if isinstance(groups, str) \
                        else groups

                    # Only the StringLike operator allows globbing or ?
                    # Technically the * and ? values are legal in StringEquals,
                    # but we don't allow them for clarity
                    if (operator in UNGLOBBABLE_OPERATORS and
                        any([
                            ["*" in group for group in groups],
                            ["?" in group for group in groups]
                            ])):
                        raise ValueError

                    policy_groups.update(groups)

    return list(policy_groups)
