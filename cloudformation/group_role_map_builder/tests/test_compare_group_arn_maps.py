from ..functions.group_role_map_builder import (
    store_s3_file,
    get_s3_file
)
import boto3
from moto import mock_s3

S3_BUCKET_NAME = 'test'
S3_FILE_NAME = 'test.json'


# https://stackoverflow.com/a/23844656/168874
@mock_s3
def test_store_file():
    client = boto3.client('s3')
    client.create_bucket(Bucket=S3_BUCKET_NAME)
    beginning_group_arn_map = get_s3_file(S3_BUCKET_NAME, S3_FILE_NAME)
    assert len(beginning_group_arn_map) == 0

    first_group_arn_map_to_send = {
        'team_foo': [
            'arn:aws:iam::123456789012:role/BarRole',
            'arn:aws:iam::123456789012:role/BazRole',
        ],
        'team_qux': [
            'arn:aws:iam::123456789012:role/BarRole',
            'arn:aws:iam::123456789012:role/XyzzyRole',
        ],
    }
    new_map_updated = store_s3_file(
        S3_BUCKET_NAME, S3_FILE_NAME, first_group_arn_map_to_send, True)
    assert new_map_updated is True

    first_group_arn_map_fetched = get_s3_file(S3_BUCKET_NAME, S3_FILE_NAME)
    assert 'team_foo' in first_group_arn_map_fetched
    assert (
        'arn:aws:iam::123456789012:role/BarRole'
        in first_group_arn_map_fetched.get('team_foo', [])
    )

    first_group_arn_map_fetched_again = get_s3_file(
        S3_BUCKET_NAME,
        S3_FILE_NAME,
        first_group_arn_map_fetched
    )
    assert 'team_foo' in first_group_arn_map_fetched_again
    assert (
        'arn:aws:iam::123456789012:role/BarRole'
        in first_group_arn_map_fetched_again.get('team_foo', [])
    )
    # TODO : Somehow test that this last call to get_group_role_map triggered
    # a 304

    same_map_updated = store_s3_file(
        S3_BUCKET_NAME,
        S3_FILE_NAME,
        first_group_arn_map_to_send)
    assert same_map_updated is False
    first_group_arn_map_fetched_a_third_time = get_s3_file(
        S3_BUCKET_NAME,
        S3_FILE_NAME,
        first_group_arn_map_fetched_again
    )
    assert 'team_foo' in first_group_arn_map_fetched_a_third_time
    assert (
        'arn:aws:iam::123456789012:role/BarRole'
        in first_group_arn_map_fetched_a_third_time.get('team_foo', [])
    )

    second_group_arn_map_to_send = {
        'team_foo': ['arn:aws:iam::123456789012:role/BazRole'],
        'team_qux': [
            'arn:aws:iam::123456789012:role/BarRole',
            'arn:aws:iam::123456789012:role/XyzzyRole',
        ],
    }
    changed_map_updated = store_s3_file(
        S3_BUCKET_NAME,
        S3_FILE_NAME,
        second_group_arn_map_to_send,
        True)
    assert changed_map_updated is True

    second_group_arn_map_fetched = get_s3_file(
        S3_BUCKET_NAME,
        S3_FILE_NAME,
        second_group_arn_map_to_send
    )
    assert 'team_foo' in second_group_arn_map_fetched
    assert (
        'arn:aws:iam::123456789012:role/BarRole'
        not in second_group_arn_map_fetched.get('team_foo', [])
    )
