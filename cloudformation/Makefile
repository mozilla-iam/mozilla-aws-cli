GROUP_ROLE_MAP_BUILDER_STACK_NAME	:= GroupRoleMapBuilder
IDTOKEN_FOR_ROLES_STACK_NAME		:= IdtokenForRoles
GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX	:= group-role-map-builder
IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX		:= idtoken-for-roles

PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.infosec.mozilla.org
DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.security.allizom.org
PROD_ACCOUNT_ID		:= 371522382791
DEV_ACCOUNT_ID		:= 656532927350
PROD_S3_BUCKET_NAME	:= mozilla-infosec-auth0-rule-assets
DEV_S3_BUCKET_NAME	:= mozilla-infosec-auth0-dev-rule-assets
PROD_DOMAIN_NAME	:= roles-and-aliases.security.mozilla.org
DEV_DOMAIN_NAME		:= roles-and-aliases.security.allizom.org
PROD_DOMAIN_ZONE	:= security.mozilla.org.
DEV_DOMAIN_ZONE		:= security.allizom.org.
PROD_CERT_ARN		:= arn:aws:acm:us-west-2:371522382791:certificate/88c3077f-9b6a-490e-9d7c-67bee0f72eb4
DEV_CERT_ARN		:= arn:aws:acm:us-west-2:656532927350:certificate/46428d8b-7b26-4ad0-84d1-cd2d386e7a43
PROD_CLIENT_ID		:= N7lULzWtfVUDGymwDs0yDEq6ZcwmFazj
DEV_CLIENT_ID		:= xRFzU2bj7Lrbo3875aXwyxIArdkq1AOT
PROD_ISSUER			:= https://auth.mozilla.auth0.com/
DEV_ISSUER			:= https://auth-dev.mozilla.auth0.com/
PROD_PROVIDER_URLS	:= https://auth.mozilla.auth0.com/
DEV_PROVIDER_URLS	:= https://auth-dev.mozilla.auth0.com/,https://auth.mozilla.auth0.com/
PROD_AMR_CLAIMS		:= auth.mozilla.auth0.com/:amr
DEV_AMR_CLAIMS		:= auth-dev.mozilla.auth0.com/:amr,auth.mozilla.auth0.com/:amr

.PHONE: deploy-group-role-map-builder
deploy-group-role-map-builder:
	./deploy.sh \
		 $(PROD_ACCOUNT_ID) \
		 group_role_map_builder/group_role_map_builder.yaml \
		 $(PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(GROUP_ROLE_MAP_BUILDER_STACK_NAME) \
		 $(GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX) \
		 "S3BucketName=$(PROD_S3_BUCKET_NAME) ProviderUrls=$(PROD_PROVIDER_URLS) AmrClaims=$(PROD_AMR_CLAIMS)"

.PHONE: deploy-group-role-map-builder-dev
deploy-group-role-map-builder-dev:
	./deploy.sh \
		 $(DEV_ACCOUNT_ID) \
		 group_role_map_builder/group_role_map_builder.yaml \
		 $(DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(GROUP_ROLE_MAP_BUILDER_STACK_NAME) \
		 $(GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX) \
		 "S3BucketName=$(DEV_S3_BUCKET_NAME) ProviderUrls=$(DEV_PROVIDER_URLS) AmrClaims=$(DEV_AMR_CLAIMS)"

.PHONE: deploy-idtoken-for-roles-dev
deploy-idtoken-for-roles-dev:
	./deploy.sh \
		 $(DEV_ACCOUNT_ID) \
		 idtoken_for_roles/idtoken_for_roles.yaml \
		 $(DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(IDTOKEN_FOR_ROLES_STACK_NAME) \
		 $(IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX) \
		 "S3BucketName=$(DEV_S3_BUCKET_NAME) CustomDomainName=$(DEV_DOMAIN_NAME) DomainNameZone=$(DEV_DOMAIN_ZONE) CertificateArn=$(DEV_CERT_ARN) AllowedIssuer=$(DEV_ISSUER) AllowedAudience=$(DEV_CLIENT_ID)" \
		 AliasesEndpointUrl

.PHONE: deploy-idtoken-for-roles
deploy-idtoken-for-roles:
	./deploy.sh \
		 $(PROD_ACCOUNT_ID) \
		 idtoken_for_roles/idtoken_for_roles.yaml \
		 $(PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		 $(IDTOKEN_FOR_ROLES_STACK_NAME) \
		 $(IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX) \
		 "S3BucketName=$(PROD_S3_BUCKET_NAME) CustomDomainName=$(PROD_DOMAIN_NAME) DomainNameZone=$(PROD_DOMAIN_ZONE) CertificateArn=$(PROD_CERT_ARN) AllowedIssuer=$(PROD_ISSUER) AllowedAudience=$(PROD_CLIENT_ID)" \
		 AliasesEndpointUrl

.PHONE: test-idtoken-for-roles
test-idtoken-for-roles:
	URL=`aws cloudformation describe-stacks --stack-name $(IDTOKEN_FOR_ROLES_STACK_NAME) --query "Stacks[0].Outputs[?OutputKey=='AliasesEndpointUrl'].OutputValue" --output text` && \
	curl $$URL
