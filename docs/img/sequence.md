```mermaid
sequenceDiagram

participant FCLI as AWS Federated CLI
participant ACLI as AWS CLI
participant WB as Web Browser
participant PKCE as PKCE (Auth0)
participant AWS as AWS API
participant S3 as AWS S3

Note over FCLI: User calls AWS <br>Federated CLI with a<br> role ARN
FCLI->>FCLI: Generate state, code_verified, code_challenge
note over FCLI: Listen on :31338
FCLI->>WB: webbrowser.open(https://auth..../authorize?code_challenge=...&state=...)
WB->>PKCE: GET https://auth..../authorize?code_challenge=...&state=...
PKCE->>S3: GET group to ARN role mappings
S3->>PKCE: JSON {group to ARN role mapping}

note over PKCE: Generate id_token <br>with value <br>`amr=['group', ...]`<br>where groups are <br>filtered with mappings
WB->>FCLI: GET http://localhost:31338?code=..&state=...
note over FCLI: Request id_token<br> with our code
FCLI->>PKCE: GET https://auth.../token {code=..., state=...}
PKCE->>FCLI: JSON {id_token, access_token}
FCLI->>AWS:  GET https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity&RoleArn=...&WebIdentityToken=id_token...
note over AWS: Verify id_token <br>signature, validity
note over AWS: Verify amr contains<br> group allowed for role
AWS->>FCLI: JSON {sts token}

FCLI->>ACLI: AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... ./aws [command]
