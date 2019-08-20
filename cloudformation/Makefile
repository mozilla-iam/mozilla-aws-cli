GROUP_ROLE_MAP_BUILDER_STACK_NAME	:= GroupRoleMapBuilder
IDTOKEN_FOR_ROLES_STACK_NAME		:= IdtokenForRoles
PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.infosec.mozilla.org
DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.security.allizom.org
GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX	:= group-role-map-builder
IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX		:= idtoken-for-roles
PROD_ACCOUNT_ID	:= 371522382791
DEV_ACCOUNT_ID	:= 656532927350
PROD_GROUP_ROLE_MAP_S3_BUCKET_NAME	:= mozilla-infosec-auth0-rule-assets
DEV_GROUP_ROLE_MAP_S3_BUCKET_NAME	:= mozilla-infosec-auth0-dev-rule-assets

GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX_ARG	:= $(if $(GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX),--s3-prefix $(GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX),"")
IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX_ARG	:= $(if $(IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX),--s3-prefix $(IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX),"")

.PHONE: deploy-group-role-map-builder
deploy-group-role-map-builder:
	# Confirm that we have access to AWS and we're in the right account
	aws sts get-caller-identity --output text | grep $(PROD_ACCOUNT_ID) >/dev/null
	# This tempfile is required because of https://github.com/aws/aws-cli/issues/2504
	$(eval TMPFILE := $(shell mktemp --suffix .yaml))
	aws cloudformation package --template group_role_map_builder.yaml \
		--s3-bucket $(PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		$(GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX_ARG) \
		--output-template-file $(TMPFILE)
	aws cloudformation deploy --template-file $(TMPFILE) --stack-name $(GROUP_ROLE_MAP_BUILDER_STACK_NAME) \
	 	--capabilities CAPABILITY_IAM \
		--parameter-overrides \
			S3BucketName=$(PROD_GROUP_ROLE_MAP_S3_BUCKET_NAME)
	rm $(TMPFILE)

.PHONE: deploy-group-role-map-builder-dev
deploy-group-role-map-builder-dev:
	# Confirm that we have access to AWS and we're in the right account
	aws sts get-caller-identity --output text  | grep $(DEV_ACCOUNT_ID) >/dev/null
	# This tempfile is required because of https://github.com/aws/aws-cli/issues/2504
	$(eval TMPFILE := $(shell mktemp --suffix .yaml))
	aws cloudformation package --template group_role_map_builder/group_role_map_builder.yaml \
		--s3-bucket $(DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		$(GROUP_ROLE_MAP_BUILDER_CODE_STORAGE_S3_PREFIX_ARG) \
		--output-template-file $(TMPFILE)
	aws cloudformation deploy --template-file $(TMPFILE) --stack-name $(GROUP_ROLE_MAP_BUILDER_STACK_NAME) \
		--capabilities CAPABILITY_IAM \
		--parameter-overrides \
			S3BucketName=$(DEV_GROUP_ROLE_MAP_S3_BUCKET_NAME)
	rm $(TMPFILE)

.PHONE: deploy-idtoken-for-roles-dev
deploy-idtoken-for-roles-dev:
	# Confirm that we have access to AWS and we're in the right account
	aws sts get-caller-identity --output text  | grep $(DEV_ACCOUNT_ID) >/dev/null
	# This tempfile is required because of https://github.com/aws/aws-cli/issues/2504
	$(eval TMPFILE := $(shell mktemp --suffix .yaml))
	aws cloudformation package --template idtoken_for_roles/idtoken_for_roles.yaml \
		--s3-bucket $(DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		$(IDTOKEN_FOR_ROLES_CODE_STORAGE_S3_PREFIX_ARG) \
		--output-template-file $(TMPFILE)
	aws cloudformation deploy --template-file $(TMPFILE) --stack-name $(IDTOKEN_FOR_ROLES_STACK_NAME) \
		--capabilities CAPABILITY_IAM \
		--parameter-overrides \
			S3BucketName=$(DEV_GROUP_ROLE_MAP_S3_BUCKET_NAME)
	rm $(TMPFILE)
	# This only works when it's stack create not a stack update
	# aws cloudformation wait stack-create-complete --stack-name  $(IDTOKEN_FOR_ROLES_STACK_NAME)
	aws cloudformation describe-stacks --stack-name $(IDTOKEN_FOR_ROLES_STACK_NAME) --query "Stacks[0].Outputs[?OutputKey=='ApiEndpointUrl'].OutputValue" --output text

.PHONE: test-idtoken-for-roles-dev
test-idtoken-for-roles-dev:
	URL=`aws cloudformation describe-stacks --stack-name $(IDTOKEN_FOR_ROLES_STACK_NAME) --query "Stacks[0].Outputs[?OutputKey=='ApiEndpointUrl'].OutputValue" --output text` && \
	curl -d '{"foo":"bar", "baz":"buz"}' -H "Content-Type: application/json" -X POST $$URL
