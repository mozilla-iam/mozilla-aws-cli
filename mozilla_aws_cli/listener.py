import errno
import logging
import os.path
import socket

from flask import Flask, jsonify, request, send_from_directory
from operator import itemgetter

from .utils import exit_sigint


# These ports must be configured in the IdP's allowed callback URL list
# TODO: Move this to the CLI / config section
POSSIBLE_PORTS = [10800, 10801, 20800, 20801, 30800, 30801,
                  40800, 40801, 50800, 50801, 60800, 60801]

STATIC_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "static")
app = Flask(__name__)
logger = logging.getLogger(__name__)
login = {
    "get_id_token": None,
    "id": -1,
    "role_map": {},
}


def get_available_port():
    """Find an available port on localhost and return it.

    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for port in POSSIBLE_PORTS:
        try:
            s.bind(("127.0.0.1", port))
            s.close()
            return port
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                logger.debug("Port {} is in use".format(port))
                pass
            else:
                raise
    raise socket.gaierror("No ports available for listener")


port = get_available_port()


@app.route("/<path:filename>")
def catch_all(filename):
    r = send_from_directory(STATIC_DIR, filename)

    # there is no reason to have caching on localhost, and it makes
    # debugging considerably harder
    r.cache_control.max_age = 0

    return r


@app.route("/api/roles", methods=["POST"])
def set_role():
    login.role_arn = request.json.get("arn")

    return jsonify({
        "result": "set_role_arn",
        "status_code": 200,
    })


@app.route("/api/roles", methods=["GET"])
def get_roles():
    roles = {}
    for arn in login.role_map["roles"]:
        account_id = arn.split(":")[4]
        alias = login.role_map.get("aliases", {}).get(account_id, [account_id])[0]

        role = {
            "alias": alias,
            "arn": arn,
            "id": account_id,
            "role": arn.split(':')[5].split('/')[-1],
        }

        if alias in roles:
            roles[alias].append(role)
        else:
            roles[alias] = [role]

    # Sort the list by role name
    for alias in roles:
        roles[alias] = sorted(roles[alias], key=itemgetter("role"))

    # Set the state to stop polling for new roles
    login.state = "awaiting_role"

    return jsonify(roles)


@app.route("/api/state")
def get_state():
    if request.args.get("id") != login.id:
        return jsonify({
            "result": "invalid_id",
            "status_code": 500,
        })

    return jsonify({
        "state": login.state,
        "value": login.web_state,
    })


@app.route("/redirect_uri")
def handle_oidc_redirect():
    """Handles the redirect from Auth0, returning the user a web page which
    causes the user's web browser to make a backend call to /redirect_callback.
    The page itself tells the user that they can close the page.

    :return: html page
    """
    logger.debug(
        "Listener received a call to /redirect_uri with query parameters:\n"
        "%{args}".format(args=request.args))

    return catch_all("index.html")


@app.route("/redirect_callback", methods=["POST"])
def handle_oidc_redirect_callback():
    logger.debug(
        'Listener received a POST to /redirect_callback with a payload of '
        '{}'.format(request.json))

    if request.json.get("state", "").split("-")[0] != login.id:
        return jsonify({
            "result": "invalid_id",
            "status_code": 500,
        })

    # callback into the login.callback() function in login.py
    login.get_id_token(**request.json)

    # Send the signal to kill the application
    return jsonify({
        "result": "finished",
        "status_code": 200,
    })


@app.route("/shutdown", methods=["GET"])
def handle_shutdown():
    logger.debug("Shutting down Flask")
    exit_sigint()

    # this is down to prevent race conditions
    return jsonify({
        "result": "shutdown",
        "status_code": 200,
    })


def listen(login):
    # set the global callback
    globals()["login"] = login

    debug = True if logger.level == logging.DEBUG else False

    # Disable flask logging unless we're at DEBUG
    if not debug:
        os.environ["WERKZEUG_RUN_MAIN"] = "true"
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

    app.run(port=port, debug=debug)

    return port


if __name__ == "__main__":
    listen()
