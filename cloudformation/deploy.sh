#!/bin/bash -e

# 656532927350
ACCOUNT_ID=$1
# idtoken_for_roles/idtoken_for_roles.yaml
TEMPLATE_FILENAME=$2
# DEV_LAMBDA_CODE_STORAGE_S3_BUCKET_NAME
S3_BUCKET=$3
# GroupRoleMapBuilder
STACK_NAME=$4

# Optional arguments

# group-role-map-builder
S3_PREFIX=$5
if [ "$S3_PREFIX" != "none" ]; then
  S3_PREFIX_ARG="--s3-prefix $S3_PREFIX"
fi
# ApiEndpointUrl
if [ "$6" != "none" ]; then
  OUTPUT_VAR_NAME=$6
fi

# Confirm that we have access to AWS and we're in the right account
if ! aws sts get-caller-identity --output text |& grep $ACCOUNT_ID >/dev/null; then
  echo "Unable to access AWS or wrong account"
  exit 1
fi

# This tempfile is required because of https://github.com/aws/aws-cli/issues/2504
TMPFILE=$(mktemp --suffix .yaml)
TMPDIR=$(mktemp --directory)
trap "{ rm -f $TMPFILE;rm -rf $TMPDIR;rm -f build; }" EXIT

TARGET_PATH="`dirname \"${TEMPLATE_FILENAME}\"`"
ln --no-dereference --force --symbolic $TMPDIR "${TARGET_PATH}/build"
pip install --target "${TARGET_PATH}/build/" -r "${TARGET_PATH}/requirements.txt"
cp --verbose "${TARGET_PATH}/functions/"*.py "${TARGET_PATH}/build/"

aws cloudformation package \
  --template $TEMPLATE_FILENAME \
  --s3-bucket $S3_BUCKET \
  $S3_PREFIX_ARG \
  --output-template-file $TMPFILE

if [ "$(aws cloudformation describe-stacks --query "length(Stacks[?StackName=='${STACK_NAME}'])")" = "1" ]; then
  # Stack already exists, it will be updated
  wait_verb=stack-update-complete
else
  # Stack doesn't exist it will be created
  wait_verb=stack-create-complete
fi

aws cloudformation deploy --template-file $TMPFILE --stack-name $STACK_NAME \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    S3BucketName=$S3_BUCKET

echo "Waiting for stack to reach a COMPLETE state"
aws cloudformation wait $wait_verb --stack-name  $STACK_NAME

if [ "$OUTPUT_VAR_NAME" ]; then
  aws cloudformation describe-stacks --stack-name $STACK_NAME --query "Stacks[0].Outputs[?OutputKey=='${OUTPUT_VAR_NAME}'].OutputValue" --output text
fi
