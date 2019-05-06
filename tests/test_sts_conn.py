from auth0 import FakeBearer, rsa_public_key


from federated_aws_cli.sts_conn import deserialize_bearer_token


class TestSTSConn():

    def setup(self):
        self.fb = FakeBearer()

    def test_good_bearer_token(self):
        deserialize_bearer_token(
            self.fb.generate_bearer_without_scope(),
            rsa_public_key
        )
