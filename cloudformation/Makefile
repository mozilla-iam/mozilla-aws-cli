STACK_NAME		:= GroupRoleMapBuilder
PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.security.mozilla.org
DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME	:= public.us-west-2.security.allizom.org
LAMBDA_CODE_STORAGE_S3_PREFIX		:= group-role-map-builder
PROD_ACCOUNT_ID	:= 371522382791
DEV_ACCOUNT_ID	:= 656532927350
DEV_GROUP_ROLE_MAP_S3_BUCKET_NAME	:= mozilla-infosec-auth0-dev-rule-assets

LAMBDA_CODE_STORAGE_S3_PREFIX_ARG	:= $(if $(LAMBDA_CODE_STORAGE_S3_PREFIX),--s3-prefix $(LAMBDA_CODE_STORAGE_S3_PREFIX),"")

.PHONE: deploy
deploy:
	# Confirm that we have access to AWS and we're in the right account
	aws sts get-caller-identity --output text | grep $(PROD_ACCOUNT_ID) >/dev/null
	# This tempfile is required because of https://github.com/aws/aws-cli/issues/2504
	$(eval TMPFILE := $(shell mktemp --suffix .yaml))
	aws cloudformation package --template group_role_map_builder.yaml \
		--s3-bucket $(PROD_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		$(LAMBDA_CODE_STORAGE_S3_PREFIX_ARG) \
		--output-template-file $(TMPFILE)
	aws cloudformation deploy --template-file $(TMPFILE) --stack-name $(STACK_NAME) --capabilities CAPABILITY_IAM
	rm $(TMPFILE)

.PHONE: deploy-dev
deploy-dev:
	# Confirm that we have access to AWS and we're in the right account
	aws sts get-caller-identity --output text  | grep $(DEV_ACCOUNT_ID) >/dev/null
	# This tempfile is required because of https://github.com/aws/aws-cli/issues/2504
	$(eval TMPFILE := $(shell mktemp --suffix .yaml))
	aws cloudformation package --template group_role_map_builder.yaml \
		--s3-bucket $(DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME) \
		$(S3_PREFIX_ARG) \
		--output-template-file $(TMPFILE)
	aws cloudformation deploy --template-file $(TMPFILE) --stack-name $(STACK_NAME) \
		--capabilities CAPABILITY_IAM \
		--parameter-overrides \
			S3BucketName=$(DEV_GROUP_ROLE_MAP_S3_BUCKET_NAME)
	rm $(TMPFILE)
