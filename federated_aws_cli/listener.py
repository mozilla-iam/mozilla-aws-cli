from federated_aws_cli.login import login
from flask import Flask, jsonify, request, send_from_directory
import logging
import os.path
import signal
import socket
import errno


# These ports must be configured in the IdP's allowed callback URL list
POSSIBLE_PORTS = [10800, 10801, 20800, 20801, 30800, 30801, 40800, 40801, 50800, 50801, 60800, 60801]

app = Flask(__name__)
static_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "static")
logger = logging.getLogger(__name__)

# Until we figure out how to emit data from RequestHandler, we'll use globals =(
code = None
state = None
error_message = None


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
    return send_from_directory(static_dir, filename)


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

    # callback into the login function
    success = login.callback(
        code=request.json["code"],
        state=request.json["state"]
    )

    # let's shut this whole operation down
    if request.environ.get("werkzeug.server.shutdown"):
        logger.debug("Shutting down Flask")
        os.kill(os.getpid(), signal.SIGINT)

    logger.debug("Callback successfully handled")

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


def run():
    debug = logger.level == 10  # DEBUG

    # Disable flask logging unless we're at DEBUG
    if not debug:
        os.environ["WERKZEUG_RUN_MAIN"] = "true"
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

    app.run(port=port, debug=debug)

    return port


def main():
    run()

    # c, s, e = get_code(port)
    # logger.debug("code is {}".format(c))
    # logger.debug("state is {}".format(s))
    # logger.debug("error is {}".format(e))


if __name__ == "__main__":
    main()
