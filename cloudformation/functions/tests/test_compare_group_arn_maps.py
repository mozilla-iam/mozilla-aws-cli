from unittest.mock import patch
from ..compare_group_arn_maps import (
    store_group_arn_map,
    get_group_role_map,
    S3_BUCKET_NAME,
)
from .. import compare_group_arn_maps
import boto3
from moto import mock_s3

# https://stackoverflow.com/a/23844656/168874
@mock_s3
@patch.object(compare_group_arn_maps, 'emit_event_to_mozdef')
def test_store_group_arn_map(emit_event_to_mozdef):
    client = boto3.client('s3')
    client.create_bucket(Bucket=S3_BUCKET_NAME)
    beginning_group_arn_map = get_group_role_map()
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
    new_map_updated = store_group_arn_map(first_group_arn_map_to_send)
    assert new_map_updated is True
    emit_event_to_mozdef.assert_called_with(
        set(first_group_arn_map_to_send.keys()),
        set(),
        set(
            first_group_arn_map_to_send['team_foo']
            + first_group_arn_map_to_send['team_qux']
        ),
        set(),
        dict(),
    )

    first_group_arn_map_fetched = get_group_role_map()
    assert 'team_foo' in first_group_arn_map_fetched
    assert (
        'arn:aws:iam::123456789012:role/BarRole'
        in first_group_arn_map_fetched.get('team_foo', [])
    )

    first_group_arn_map_fetched_again = get_group_role_map(
        first_group_arn_map_fetched
    )
    assert 'team_foo' in first_group_arn_map_fetched_again
    assert (
        'arn:aws:iam::123456789012:role/BarRole'
        in first_group_arn_map_fetched_again.get('team_foo', [])
    )
    # TODO : Somehow test that this last call to get_group_role_map triggered
    # a 304

    same_map_updated = store_group_arn_map(first_group_arn_map_to_send)
    assert same_map_updated is False
    first_group_arn_map_fetched_a_third_time = get_group_role_map(
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
    changed_map_updated = store_group_arn_map(second_group_arn_map_to_send)
    assert changed_map_updated is True
    emit_event_to_mozdef.assert_called_with(
        set(),
        set(),
        set(),
        set(),
        {
            'arn:aws:iam::123456789012:role/BarRole': {
                'new_groups': {'team_qux'},
                'old_groups': {'team_qux', 'team_foo'},
            }
        }
    )

    second_group_arn_map_fetched = get_group_role_map(
        second_group_arn_map_to_send
    )
    assert 'team_foo' in second_group_arn_map_fetched
    assert (
        'arn:aws:iam::123456789012:role/BarRole'
        not in second_group_arn_map_fetched.get('team_foo', [])
    )
