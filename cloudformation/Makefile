GROUP_ROLE_MAP_BUILDER_STACK_NAME	:= GroupRoleMapBuilder
IDTOKEN_FOR_ROLES_STACK_NAME		:= IdtokenForRoles
PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.infosec.mozilla.org
DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.security.allizom.org
GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX	:= group-role-map-builder
IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX		:= idtoken-for-roles
PROD_ACCOUNT_ID	:= 371522382791
DEV_ACCOUNT_ID	:= 656532927350
PROD_S3_BUCKET_NAME	:= mozilla-infosec-auth0-rule-assets
DEV_S3_BUCKET_NAME	:= mozilla-infosec-auth0-dev-rule-assets

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
		 ApiEndpointUrl

.PHONE: test-idtoken-for-roles-dev
test-idtoken-for-roles-dev:
	URL=`aws cloudformation describe-stacks --stack-name $(IDTOKEN_FOR_ROLES_STACK_NAME) --query "Stacks[0].Outputs[?OutputKey=='ApiEndpointUrl'].OutputValue" --output text` && \
	curl -d '{"foo":"bar", "baz":"buz"}' -H "Content-Type: application/json" -X POST $$URL
