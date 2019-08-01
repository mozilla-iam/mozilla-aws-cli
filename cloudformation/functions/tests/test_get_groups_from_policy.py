import builtins
import json
import os
import os.path
from cloudformation.functions.get_groups_from_policy import (
    get_groups_from_policy
)


# Open every policy in the policies directory
__policies_dir = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "policies"
)
policies = []
for filename in os.listdir(__policies_dir):
    with open(os.path.join(__policies_dir, filename), "r") as f:
        policies.append(json.load(f))


def test_all_policies():
    for policy in policies:
        if "Returns" in policy:
            assert(sorted(get_groups_from_policy(policy)) ==
                   sorted(policy["Returns"]))
        elif "Exception" in policy:
            try:
                get_groups_from_policy(policy)
            except getattr(builtins, policy["Exception"]):
                pass
        else:
            raise ValueError


if __name__ == "__main__":
    test_all_policies()
