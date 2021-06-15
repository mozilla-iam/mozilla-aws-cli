import os
import stat
import json.decoder
import logging
import platform
import requests
import tempfile

from .cache import read_group_role_map, write_group_role_map


logger = logging.getLogger(__name__)

PROMPT_BASH_CODE = r'''
function maws_profile {
    if [[ -n $MAWS_PROMPT ]]; then
        # either a whitespace character or blank, depending on what
        # was selected by the prompt injection routine below.
        echo -n "$MAWS_PROMPT_PREFIX"
        if [[ -n $AWS_SESSION_EXPIRATION && "$(date +%s)" -gt $AWS_SESSION_EXPIRATION ]]; then
            echo -n "(maws keys expired)"
        else
            echo -n "(${MAWS_PROMPT})"
        fi
        # either a whitespace character or blank, depending on what
        # followed the maws substitution point in the original prompt
        echo -n "$MAWS_PROMPT_SUFFIX"
    fi
}

# zsh requires this in order to evaluate the prompt dynamically like bash
[[ -n "$ZSH_VERSION" ]] && setopt prompt_subst

# if the user hasn't disabled prompt injection,
# and we aren't already injecting maws_profile:
if [[ -z $MAWS_PROMPT_DISABLE && $PS1 != *'$(maws_profile)' ]]; then
    # by default, we prefix but not suffix; good for example '\w\$',
    # but has to be overridden below for various whitespace cases.
    MAWS_PROMPT_PREFIX=" " MAWS_PROMPT_SUFFIX=""
    # maws_profile is missing from PS1
    if [[ $PS1 == *'\$ ' ]]; then
        # prompt ends with dynamic '\$ '
        # if the original prompt surrounds the final '\$' with whitespace,
        # we surround the substitution with whitespace to maintain that.
        [[ $PS1 == *' \$ ' ]] && MAWS_PROMPT_PREFIX="" MAWS_PROMPT_SUFFIX=" "
        # inject our substitution before the original '$ '
        PS1="${PS1%\\$ }\$(maws_profile)\\$ "
    elif [[ $PS1 == *'$ ' ]]; then
        # prompt ends with hard-coded '$ '
        # if the original prompt surrounds the final '$' with whitespace,
        # we surround the substitution with whitespace to maintain that.
        [[ $PS1 == *' $ ' ]] && MAWS_PROMPT_PREFIX="" MAWS_PROMPT_SUFFIX=" "
        # inject our substitution before the original '$ '
        PS1="${PS1%\$ }\$(maws_profile)\$ "
    elif [[ $PS1 == *'%# ' ]]; then
        # prompt ends with dynamic '%# '
        # if the original prompt surrounds the final '$' with whitespace,
        # we only suffix bot not prefix with whitespace to maintain that.
        [[ $PS1 == *' %# ' ]] && MAWS_PROMPT_PREFIX="" MAWS_PROMPT_SUFFIX=" "
        # inject our substitution before the original '%# '
        PS1="${PS1%\%# }\$(maws_profile)%# "
    else
        # we're the last entry in the prompt, so we don't need extra whitespace.
        # if the original prompt ends with whitespace,
        # we don't need to prefix whitespace ourselves.
        [[ $PS1 == *' ' ]] && MAWS_PROMPT_PREFIX=""
        # inject our substitution before the original '%# '
        PS1="${PS1}\$(maws_profile) "
    fi
fi
'''


def output_set_env_vars(var_map, message=None):
    if platform.system() == "Windows":
        result = "\n".join(
            ["set {}={}".format(x, var_map[x]) for x in var_map])
    else:
        name = tempfile.mkstemp(suffix=".sh", prefix="maws-")[1]
        with open(name, "w") as f:
            vars_to_set = [
                "=".join((x, str(var_map[x])))
                for x in var_map if var_map[x] is not None]
            if vars_to_set:
                f.write("export {}\n".format(" ".join(vars_to_set)))
                f.write('alias maws-logout="unset {}"\n'.format(
                    " ".join([x for x in var_map if var_map[x] is not None])))
            vars_to_unset = [x for x in var_map if var_map[x] is None]
            if vars_to_unset:
                f.write("unset {}\n".format(" ".join(vars_to_unset)))

            if message is not None:
                f.write('>&2 echo "{}"\n'.format(message))

            f.write("{}\n".format(PROMPT_BASH_CODE))
            f.write("rm -f {}\n".format(name))
            result = "source {}".format(name)
        st = os.stat(name)
        os.chmod(name, st.st_mode | stat.S_IEXEC)

    return result


def get_roles_and_aliases(endpoint, token, key, cache=True):
    role_map = read_group_role_map(endpoint)

    if role_map is None or not cache:
        headers = {"Content-Type": "application/json"}
        body = {
            "token": token,
            "key": key,
            "cache": cache
        }

        logging.debug("Getting roles and aliases from {} by POSTing {}".format(
            endpoint,
            body
        ))

        try:
            role_map = requests.post(
                endpoint, headers=headers, json=body).json()
        except requests.exceptions.ConnectionError as e:
            role_map = {"error": str(e)}
        except json.decoder.JSONDecodeError:
            logging.error("Unable to parse role map.")
            return None

        if role_map is None:
            logging.error(
                "Unable to retrieve role map at: {}. Please check your "
                "URL.".format(endpoint))
            return None
        elif "error" in role_map or "roles" not in role_map:
            if "message" in role_map and "error" not in role_map:
                role_map["error"] = role_map["message"]

            logging.error(
                "Unable to retrieve role map: {}".format(role_map["error"]))
            return None
        else:
            write_group_role_map(endpoint, role_map)

    return role_map
