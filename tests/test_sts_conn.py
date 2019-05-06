from auth0 import FakeBearer


class TestSTSConn():
    def setup(self):
        self.fb = FakeBearer()
        # use wity self.fb.generate_bearer_without_scope()
