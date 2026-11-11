import boto3

from scanner.checks.cloudtrail import (
    log_file_validation,
    logs_encrypted_with_kms,
    multi_region_trail_logging,
)
from scanner.models import Status


def make_trail(
    name="main-trail",
    *,
    multi_region=True,
    logging=True,
    read_write="All",
    log_validation=False,
    kms_key_id=None,
):
    """Create a trail in the fake AWS. Each argument can break one thing."""
    bucket = f"{name}-logs"
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=bucket)
    trails = boto3.client("cloudtrail", region_name="us-east-1")
    extra = {"KmsKeyId": kms_key_id} if kms_key_id else {}
    trails.create_trail(
        Name=name,
        S3BucketName=bucket,
        IsMultiRegionTrail=multi_region,
        EnableLogFileValidation=log_validation,
        **extra,
    )
    trails.put_event_selectors(
        TrailName=name,
        EventSelectors=[{"ReadWriteType": read_write, "IncludeManagementEvents": True}],
    )
    if logging:
        trails.start_logging(Name=name)
    return trails


def by_trail(records):
    return {r.resource.rsplit("/", 1)[-1]: r for r in records}


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

# ---- CT-12 log file validation ------------------------------------------------------------


def test_ct_12_fails_when_the_account_has_no_trail(ctx):
    [record] = log_file_validation.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"trails_found": 0}


def test_ct_12_fails_when_validation_is_off(ctx):
    make_trail(log_validation=False)
    [record] = log_file_validation.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"log_file_validation": False}


def test_ct_12_passes_when_validation_is_on(ctx):
    make_trail(log_validation=True)
    [record] = log_file_validation.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence == {"log_file_validation": True}


def test_ct_12_every_trail_is_its_own_result(ctx):
    make_trail("trail-one", log_validation=True)
    make_trail("trail-two", log_validation=False)
    records = by_trail(log_file_validation.run(ctx))
    assert records["trail-one"].status is Status.PASS
    assert records["trail-two"].status is Status.FAIL


# ---- CT-13 KMS encryption -----------------------------------------------------------------

KEY = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"


def test_ct_13_fails_when_the_account_has_no_trail(ctx):
    [record] = logs_encrypted_with_kms.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"trails_found": 0}


def test_ct_13_fails_when_the_trail_has_no_kms_key(ctx):
    make_trail()
    [record] = logs_encrypted_with_kms.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"kms_key_id": None}


def test_ct_13_passes_and_records_the_key(ctx):
    make_trail(kms_key_id=KEY)
    [record] = logs_encrypted_with_kms.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence == {"kms_key_id": KEY}


def test_ct_13_every_trail_is_its_own_result(ctx):
    make_trail("trail-one", kms_key_id=KEY)
    make_trail("trail-two")
    records = by_trail(logs_encrypted_with_kms.run(ctx))
    assert records["trail-one"].status is Status.PASS
    assert records["trail-two"].status is Status.FAIL