import builtins
import os
import os.path
import pytest


from ..functions.group_role_map_builder import (  # noqa, called via globals()
    get_groups_from_policy,
    InvalidPolicyError,
    UnsupportedPolicyError
)
from json import loads
from json.decoder import JSONDecodeError
from pytest import raises

# Open every policy in the policies directory
__policies_dir = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "policies"
)
policies = []
for filename in os.listdir(__policies_dir):
    with open(os.path.join(__policies_dir, filename), "r") as f:
        raw = f.read()

        # some of the policies are intentionally broken, and that's okay
        try:
            parsed = loads(raw)
        except JSONDecodeError:
            parsed = {}

        policies.append({
            "raw": raw,
            "parsed": parsed,
            "filename": filename,  # not necessary, but helps with debugging
        })


def test_all_policies(monkeypatch):
    monkeypatch.setenv('VALID_AMRS', 'auth.example.auth0.com/:amr')
    monkeypatch.setenv(
        'VALID_FEDERATED_PRINCIPAL_URLS',
        'https://auth.example.auth0.com/')
    for policy in policies:
        # convenience variables
        raw = policy["raw"]
        parsed = policy["parsed"]

        if "Returns" in parsed:
            result = get_groups_from_policy(raw)
            assert (sorted(result) == sorted(parsed["Returns"])), (
                "Expected {} to return {}. Instead it returned {} where "
                "VALID_AMRS is {} and VALID_FEDERATED_PRINCIPAL_KEYS is "
                "{}".format(
                    policy["filename"],
                    parsed["Returns"],
                    result,
                    os.getenv('VALID_AMRS'),
                    os.getenv('VALID_FEDERATED_PRINCIPAL_KEYS'),
                ))

        elif "Exception" in parsed:
            exception = getattr(builtins, parsed["Exception"], None) or \
                globals().get(parsed["Exception"])

            # if there's an exception, it has to exist _somewhere_, or we've
            # really messed up
            if exception is None:
                pytest.fail('Unable to find exception {}'.format(
                    parsed["Exception"]
                ))
                raise NameError

            try:
                with raises(exception):
                    get_groups_from_policy(raw)
                    pytest.fail(
                        'Expected {} to raise exception {} but it did '
                        'not'.format(policy["filename"], exception))
            except Exception as excinfo:
                pytest.fail(
                    'Expected {} to raise exception {} but instead it raised '
                    '{} was : {}'.format(
                        policy["filename"], exception, type(excinfo), excinfo))
                raise
        # These should be things that aren't JSON
        else:
            with raises(InvalidPolicyError):
                get_groups_from_policy(raw)
