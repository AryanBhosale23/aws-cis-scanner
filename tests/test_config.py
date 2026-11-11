import boto3

from scanner.checks.config import config_recorder_on
from scanner.models import Status

ROLE = "arn:aws:iam::123456789012:role/config-role"


def make_recorder(*, all_supported=True, recording=True):
    """Create an AWS Config recorder in the fake AWS. Each argument can break one thing."""
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="config-bucket")
    config = boto3.client("config", region_name="us-east-1")
    group = (
        {"allSupported": True, "includeGlobalResourceTypes": True}
        if all_supported
        else {"allSupported": False, "resourceTypes": ["AWS::S3::Bucket"]}
    )
    config.put_configuration_recorder(
        ConfigurationRecorder={"name": "default", "roleARN": ROLE, "recordingGroup": group}
    )
    config.put_delivery_channel(
        DeliveryChannel={"name": "default", "s3BucketName": "config-bucket"}
    )
    if recording:
        config.start_configuration_recorder(ConfigurationRecorderName="default")


# ---- CFG-14 AWS Config recorder -----------------------------------------------------------


def test_cfg_14_fails_when_there_is_no_recorder(ctx):
    [record] = config_recorder_on.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"recorders_found": 0}


def test_cfg_14_fails_when_the_recorder_was_never_started(ctx):
    make_recorder(recording=False)
    [record] = config_recorder_on.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["recording"] is False


def test_cfg_14_fails_when_only_some_resource_types_are_recorded(ctx):
    make_recorder(all_supported=False)
    [record] = config_recorder_on.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence["all_supported"] is False


def test_cfg_14_passes_when_all_supported_resources_are_recorded(ctx):
    make_recorder()
    [record] = config_recorder_on.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence["all_supported"] is True
    assert record.evidence["recording"] is True