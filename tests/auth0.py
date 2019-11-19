from jose import jws


rsa_private_key = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

rsa_public_key = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtSKfSeI0fukRIX38AHlK
B1YPpX8PUYN2JdvfM+XjNmLfU1M74N0VmdzIX95sneQGO9kC2xMIE+AIlt52Yf/K
gBZggAlS9Y0Vx8DsSL2HvOjguAdXir3vYLvAyyHin/mUisJOqccFKChHKjnk0uXy
/38+1r17/cYTp76brKpU1I4kM20M//dbvLBWjfzyw9ehufr74aVwr+0xJfsBVr2o
aQFww/XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M733Ea8a7HxtZS563/
mhhRZLU5aynQpwaVv2U++CL6EvGt8TlNZOkeRv8wz+Rt8B70jzoRpVK36rR+pHKl
XhMGT619v82LneTdsqA25Wi2Ld/c0niuul24A6+aaj2u9SWbxA9LmVtFntvNbRaH
XE1SLpLPoIp8uppGF02Nz2v3ld8gCnTTWfq/BQ80Qy8e0coRRABECZrjIMzHEg6M
loRDy4na0pRQv61VogqRKDU2r3/VezFPQDb3ciYsZjWBr3HpNOkUjTrvLmFyOE9Q
5R/qQGmc6BYtfk5rn7iIfXlkJAZHXhBy+ElBuiBM+YSkFM7dH92sSIoZ05V4MP09
Xcppx7kdwsJy72Sust9Hnd9B7V35YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2
Ks3IHH7tVltM6NsRk3jNdVMCAwEAAQ==
-----END PUBLIC KEY-----"""

json_form_of_pk = {
    u'keys': [
        {
            u'alg': u'RS256',
            u'e': u'AQAB',
            u'kid': u'6758b0b8eb341e90454860432d6a1648bf4de03b',
            u'kty': u'RSA',
            u'n': str(
                'ALUin0niNH7pESF9_AB5SgdWD6V_D1GDdiXb3zPl4zZi31NTO-DdFZncyF_ebJ3kBjvZAtsTCBPgCJbedmH_'
                'yoAWYIAJUvWNFcfA7Ei9h7zo4LgHV4q972C7wMsh4p_5lIrCTqnHBSgoRyo55NLl8v9_Pta9e_3GE6e-m6yqVNSOJDNtDP_'
                '3W7ywVo388sPXobn6--GlcK_tMSX7AVa9qGkBcMP1xxs-vUO8hyug28WDuMOKtrCH3AuKU_'
                'F0zx6OCWdjO99xGvGux8bWUuet_5oYUWS1OWsp0KcGlb9lPvgi-hLxrfE5TWTpHkb_MM_kbfAe9I86EaVSt-q0fqRypV4TBk-tfb_'
                'Ni53k3bKgNuVoti3f3NJ4rrpduAOvmmo9rvUlm8QPS5lbRZ7bzW0Wh1xNUi6Sz6CKfLqaRhdNjc9r95XfIAp001n6vwUPNEMvHtHKE'
                'UQARAma4yDMxxIOjJaEQ8uJ2tKUUL-tVaIKkSg1Nq9_1XsxT0A293ImLGY1ga9x6TTpFI067y5hcjhPUOUf6kBpnOgWLX5Oa5-4iH1'
                '5ZCQGR14QcvhJQbogTPmEpBTO3R_drEiKGdOVeDD9PV3Kace5HcLCcu9krrLfR53fQe1d-WJ1Relu_dZVR53p4QiTs4kZpB-MSy2z5'
                'Gkk9irNyBx-7VZbTOjbEZN4zXVT'
            ),
            u'use': u'sig'
        }
    ]
}


class FakeBearer(object):
    def __init__(self):
        self.fake_signing_key_private = rsa_private_key
        self.fake_signing_key_public = rsa_public_key
        self.additional_headers = {'kid': u'6758b0b8eb341e90454860432d6a1648bf4de03b'}

    def generate_bearer_without_scope(self, bad_claims=None):
        claims = {
            "access_token": "12345",
            "id_token": "eyJ0XAifaeEoQ",
            "token_type": "Bearer"
        }
        return jws.sign(claims, self.fake_signing_key_private, headers=self.additional_headers, algorithm='RS256')

    # def generate_bearer_with_scope(self, scope, bad_claims=None):
    #     claims = {
    #         'iss': 'https://auth-dev.mozilla.auth0.com/',
    #         'sub': 'mc1l0G4sJI2eQfdWxqgVNcRAD9EAgHib@clients',
    #         'aud': 'https://mozilla-aws-cli',
    #         'iat': (datetime.utcnow() - timedelta(seconds=3100)).strftime('%s'),
    #         'exp': (datetime.utcnow() + timedelta(seconds=3100)).strftime('%s'),
    #         'scope': scope,
    #         'gty': 'client-credentials'
    #     }

    #     if bad_claims is not None:
    #         claims = bad_claims

    #     return jws.sign(claims, self.fake_signing_key_private, headers=self.additional_headers, algorithm='RS256')
