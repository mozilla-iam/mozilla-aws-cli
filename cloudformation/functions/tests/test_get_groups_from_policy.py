import builtins
import os
import os.path

from cloudformation.functions.get_groups_from_policy import (  # noqa, called via globals()
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


def test_all_policies():
    for policy in policies:
        # convenience variables
        raw = policy["raw"]
        parsed = policy["parsed"]

        if "Returns" in parsed:
            assert(sorted(get_groups_from_policy(raw)) ==
                   sorted(parsed["Returns"]))

        elif "Exception" in parsed:
            exception = getattr(builtins, parsed["Exception"], None) or \
                globals().get(parsed["Exception"])

            # if there's an exception, it has to exist _somewhere_, or we've
            # really messed up
            if exception is None:
                raise NameError

            raises(exception, get_groups_from_policy, raw)

        # These should be things that aren't JSON
        else:
            raises(InvalidPolicyError, get_groups_from_policy, raw)


if __name__ == "__main__":
    test_all_policies()
