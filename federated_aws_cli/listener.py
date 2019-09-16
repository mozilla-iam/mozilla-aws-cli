import errno
import logging
import os.path
import socket

from flask import Flask, jsonify, request, send_from_directory


# These ports must be configured in the IdP's allowed callback URL list
# TODO: Move this to the CLI / config section
POSSIBLE_PORTS = [10800, 10801, 20800, 20801, 30800, 30801,
                  40800, 40801, 50800, 50801, 60800, 60801]

STATIC_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "static")
app = Flask(__name__)
logger = logging.getLogger(__name__)


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
    return send_from_directory(STATIC_DIR, filename)


@app.route("/redirect_uri")
def handle_oidc_redirect():
    """
    Handles the return from auth0, returning a page that indicates you can
    close everything

    :return: html page
    """
    logger.debug("redirect parameters: \n%{args}".format(args=request.args))

    return(catch_all("index.html"))


@app.route("/redirect_callback", methods=["POST"])
def handle_oidc_redirect_callback():
    logger.debug(request.json.get("code"))
    logger.debug(request.json.get("state"))

    # callback into the login function
    success = globals()["callback"](
        code=request.json["code"],
        state=request.json["state"]
    )

    # the callback should send SIGINT, but this is done to prevent
    # race conditions
    if success:
        return jsonify({
            "result": "OK",
            "status_code": 500,
        })
    else:
        return jsonify({
            "result": "OK",
            "status_code": 500,
        })


def listen(callback=None):
    # set the global callback
    globals()["callback"] = callback

    debug = logger.level == 10  # DEBUG

    # Disable flask logging unless we're at DEBUG
    if not debug:
        os.environ["WERKZEUG_RUN_MAIN"] = "true"
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

    app.run(port=port, debug=debug)

    return port


if __name__ == "__main__":
    listen()
