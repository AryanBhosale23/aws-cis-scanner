import boto3

from scanner.checks.cloudtrail import multi_region_trail_logging
from scanner.models import Status


def make_trail(*, multi_region=True, logging=True, read_write="All"):
    """Create a trail in the fake AWS. Each argument can break one thing."""
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="trail-logs-bucket")
    trails = boto3.client("cloudtrail", region_name="us-east-1")
    trails.create_trail(
        Name="main-trail", S3BucketName="trail-logs-bucket", IsMultiRegionTrail=multi_region
    )
    trails.put_event_selectors(
        TrailName="main-trail",
        EventSelectors=[{"ReadWriteType": read_write, "IncludeManagementEvents": True}],
    )
    if logging:
        trails.start_logging(Name="main-trail")
    return trails


# ---- CT-11 multi-region trail is logging --------------------------------------------------


def test_ct_11_fails_when_the_account_has_no_trail(ctx):
    [record] = multi_region_trail_logging.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"trails_found": 0, "problems": {}}


def test_ct_11_passes_for_a_healthy_multi_region_trail(ctx):
    make_trail()
    [record] = multi_region_trail_logging.run(ctx)
    assert record.status is Status.PASS
    assert record.resource.endswith(":trail/main-trail")


def test_ct_11_fails_when_the_trail_covers_one_region_only(ctx):
    make_trail(multi_region=False)
    [record] = multi_region_trail_logging.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["problems"] == {"main-trail": ["not multi-region"]}


def test_ct_11_fails_when_logging_was_never_started(ctx):
    make_trail(logging=False)
    [record] = multi_region_trail_logging.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["problems"] == {"main-trail": ["not logging"]}


def test_ct_11_fails_when_only_read_events_are_recorded(ctx):
    make_trail(read_write="ReadOnly")
    [record] = multi_region_trail_logging.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["problems"] == {
        "main-trail": ["does not record all management events"]
    }


def test_ct_11_passes_with_advanced_selectors_for_management_events(ctx):
    trails = make_trail()
    trails.put_event_selectors(
        TrailName="main-trail",
        AdvancedEventSelectors=[
            {
                "Name": "Management events selector",
                "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}],
            }
        ],
    )
    [record] = multi_region_trail_logging.run(ctx)
    assert record.status is Status.PASS