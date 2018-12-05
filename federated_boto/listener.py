import http.server
import logging
from urllib.parse import urlparse, parse_qs
import socket
import errno

# These ports must be configured in the IdP's allowed callback URL list
POSSIBLE_PORTS = [10800, 10801, 20800, 20801, 30800, 30801, 40800, 40801,
                  50800, 50801, 60800, 60801]

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Until we figure out how to emit data from RequestHandler, we'll use globals =(
code = None
state = None
error_message = None


class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global code, state, error_message
        try:
            query = parse_qs(urlparse(self.path).query)

            def get_arg(query, v):
                return next(iter(query.get(v,[])), None)

            code = get_arg(query, 'code')
            state = get_arg(query, 'state')
            error = get_arg(query, 'error')
            error_description = get_arg(query, 'error_description')
            error_message = ('{}: {}'.format(error, error_description)
                if error is not None else None)
        except Exception as e:
            self.send_response(500)
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("Please return to your application now.".encode('utf-8'))


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
                logging.debug('Port {} is in use'.format(port))
                pass
            else:
                raise
    return False


def get_code(port=POSSIBLE_PORTS[0]):
    """

    Launch listener on port
    Wait until listener is hit or timeout is met
    Return code and state passed as arguments to the callback path

    :return:
    """
    logger.debug('About to launch listener')

    try:
        httpd = http.server.HTTPServer(
            ('127.0.0.1', port),
            RequestHandler)
        httpd.handle_request()
        return code, state, error_message
    except:
        raise


def main():
    port=get_available_port()
    c, s, e = get_code(port)
    logger.debug('code is {}'.format(c))
    logger.debug('state is {}'.format(s))
    logger.debug('error is {}'.format(e))

if __name__ == "__main__":
    main()
