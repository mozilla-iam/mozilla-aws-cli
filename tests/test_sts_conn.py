from auth0 import FakeBearer, rsa_public_key


from federated_aws_cli.sts_conn import get_credentials


class TestSTSConn():

    def setup(self):
        self.fb = FakeBearer()
        # use wity self.fb.generate_bearer_without_scope()
