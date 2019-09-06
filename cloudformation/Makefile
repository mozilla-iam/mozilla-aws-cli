GROUP_ROLE_MAP_BUILDER_STACK_NAME	:= GroupRoleMapBuilder
IDTOKEN_FOR_ROLES_STACK_NAME		:= IdtokenForRoles
GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX	:= group-role-map-builder
IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX		:= idtoken-for-roles

PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.infosec.mozilla.org
DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.security.allizom.org
PROD_ACCOUNT_ID	:= 371522382791
DEV_ACCOUNT_ID	:= 656532927350
PROD_S3_BUCKET_NAME	:= mozilla-infosec-auth0-rule-assets
DEV_S3_BUCKET_NAME	:= mozilla-infosec-auth0-dev-rule-assets
PROD_DOMAIN_NAME	:= roles-and-aliases.security.mozilla.org
DEV_DOMAIN_NAME		:= roles-and-aliases.security.allizom.org
PROD_DOMAIN_ZONE	:= security.mozilla.org.
DEV_DOMAIN_ZONE		:= security.allizom.org.
PROD_CERT_ARN		:= arn:aws:acm:us-west-2:371522382791:certificate/88c3077f-9b6a-490e-9d7c-67bee0f72eb4
DEV_CERT_ARN		:= arn:aws:acm:us-west-2:656532927350:certificate/46428d8b-7b26-4ad0-84d1-cd2d386e7a43

.PHONE: deploy-group-role-map-builder
deploy-group-role-map-builder:
	./deploy.sh \
		 $(PROD_ACCOUNT_ID) \
		 group_role_map_builder/group_role_map_builder.yaml \
		 $(PROD_S3_BUCKET_NAME) \
		 $(GROUP_ROLE_MAP_BUILDER_STACK_NAME) \
		 $(GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX)

.PHONE: deploy-group-role-map-builder-dev
deploy-group-role-map-builder-dev:
	./deploy.sh \
		 $(DEV_ACCOUNT_ID) \
		 group_role_map_builder/group_role_map_builder.yaml \
		 $(DEV_S3_BUCKET_NAME) \
		 $(GROUP_ROLE_MAP_BUILDER_STACK_NAME) \
		 $(GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX)

.PHONE: deploy-idtoken-for-roles-dev
deploy-idtoken-for-roles-dev:
	./deploy.sh \
		 $(DEV_ACCOUNT_ID) \
		 idtoken_for_roles/idtoken_for_roles.yaml \
		 $(DEV_S3_BUCKET_NAME) \
		 $(IDTOKEN_FOR_ROLES_STACK_NAME) \
		 $(IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX) \
		 "CustomDomainName=$(DEV_DOMAIN_NAME) DomainNameZone=$(DEV_DOMAIN_ZONE) CertificateArn=$(DEV_CERT_ARN)" \
		 AliasesEndpointUrl

.PHONE: deploy-idtoken-for-roles
deploy-idtoken-for-roles:
	./deploy.sh \
		 $(PROD_ACCOUNT_ID) \
		 idtoken_for_roles/idtoken_for_roles.yaml \
		 $(PROD_S3_BUCKET_NAME) \
		 $(IDTOKEN_FOR_ROLES_STACK_NAME) \
		 $(IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX) \
		 "CustomDomainName=$(PROD_DOMAIN_NAME) DomainNameZone=$(PROD_DOMAIN_ZONE) CertificateArn=$(PROD_CERT_ARN)" \
		 AliasesEndpointUrl

.PHONE: test-idtoken-for-roles
test-idtoken-for-roles:
	URL=`aws cloudformation describe-stacks --stack-name $(IDTOKEN_FOR_ROLES_STACK_NAME) --query "Stacks[0].Outputs[?OutputKey=='AliasesEndpointUrl'].OutputValue" --output text` && \
	curl $$URL
