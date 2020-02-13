from __future__ import print_function
import errno
import logging
import os.path
import socket
import time

from flask import Flask, jsonify, request, send_from_directory
import requests.exceptions
from operator import itemgetter

from .utils import exit_sigint, STSWarning

try:
    # P3
    from urllib.parse import urlencode
except ImportError:
    # P2 Compat
    from urllib import urlencode

# These ports must be configured in the IdP's allowed callback URL list
# TODO: Move this to the CLI / config section
POSSIBLE_PORTS = [10800, 10801, 20800, 20801, 30800, 30801,
                  40800, 40801, 50800, 50801, 60800, 60801]

STATIC_DIR = os.path.join(os.path.dirname(
    os.path.realpath(__file__)), "static")
app = Flask(__name__)
logger = logging.getLogger(__name__)
login = {
    "get_id_token": None,
    "id": -1,
    "last_state_check": None,
    "role_map": {},
}


def get_available_port():
    """Find an available port on localhost and return it.

    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    for p in POSSIBLE_PORTS:
        try:
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                logger.debug("Port {} is in use".format(p))
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
    logger.debug("IAM Role ARN selected from role picker : {}".format(
        login.role_arn))

    return jsonify({
        "result": login.exchange_token_for_credentials(),
        "status_code": 200,
    })


@app.route("/api/roles", methods=["GET"])
def get_roles():
    roles = {}
    if login.role_map is None and login.token is not None:
        if not login.get_role_map():
            return jsonify({})
    for arn in login.role_map["roles"]:
        account_id = arn.split(":")[4]
        alias = login.role_map.get(
            "aliases", {}).get(account_id, [account_id])[0]

        role = {
            "alias": alias,
            "arn": arn,
            "id": account_id,
            "role": arn.split(":")[5].split("/")[-1],
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


@app.route("/api/heartbeat")
def get_heartbeat():
    if request.args.get("id") != login.id:
        return jsonify({
            "result": "invalid_id",
            "status_code": 500,
        })

    start = time.time()
    while time.time() - start < 30:
        if login.last_state_check is None:
            pass
        elif (time.time() - login.last_state_check >
              login.max_sleep_no_state_check):
            logger.error(
                "No response from web interface for {} seconds, shutting "
                "down.".format(login.max_sleep_no_state_check))
            exit_sigint()
        time.sleep(0.5)
    return jsonify({
        "result": "heartbeat_done",
        "status_code": 200,
    })


@app.route("/api/state")
def get_state():
    if request.args.get("id") != login.id:
        return jsonify({
            "result": "invalid_id",
            "status_code": 500,
        })

    if login.state in ["role_picker", "redirecting"]:
        # These states require calls out to external resources that may take
        # longer than 2 seconds to return
        login.max_sleep_no_state_check = 10
    else:
        login.max_sleep_no_state_check = 2

    # Update the last time state was checked
    login.last_state_check = time.time()

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
        "Listener received a POST to /redirect_callback with a payload of "
        "{}".format(request.json))

    if request.json.get("state", "").split("-")[0] != login.id:
        return jsonify({
            "result": "invalid_id",
            "status_code": 500,
        })

    # callback into the login.callback() function in login.py
    logger.debug("redirect_callback : request is {}".format(request.json))
    if not login.get_id_token(**request.json):
        return jsonify({
            "result": "error",
            "status_code": 400,
        })
    if login.validate_id_token() is None:
        return jsonify({
            "result": "id_token_validation_failed",
            "status_code": 400,
        })
    if login.role_arn is None:
        if login.batch:
            login.exit("No role_arn provided. Exiting due to batch mode.")
        else:
            login.state = "role_picker"
        return jsonify({
            "result": login.state,
            "status_code": 200,
        })

    if not login.get_role_map():
        return jsonify({
            "result": "error",
            "status_code": 400,
        })
    return jsonify({
        "result": login.exchange_token_for_credentials(),
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
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app.run(port=port, debug=debug)

    return port
