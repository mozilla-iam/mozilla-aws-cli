import base64
import hashlib
import os
import signal
import sys


def base64_without_padding(data):
    # https://tools.ietf.org/html/rfc7636#appendix-A
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def exit_sigint():
    # Close stdout/stderr before sending SIGINT, mostly to avoid `click` errors
    # See: https://github.com/mozilla-iam/federated-aws-cli/issues/88
    f = open(os.devnull, "w")
    sys.stdout = sys.stderr = f

    os.kill(os.getpid(), signal.SIGINT)


def generate_challenge(code_verifier):
    # https://tools.ietf.org/html/rfc7636#section-4.2
    return base64_without_padding(
        hashlib.sha256(code_verifier.encode()).digest())
