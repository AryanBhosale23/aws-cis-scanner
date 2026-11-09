import boto3
from botocore.exceptions import ClientError

from scanner.checks.s3 import default_encryption, public_access_block
from scanner.models import Status

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def make_bucket(name):
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=name)


def block_public_access(name):
    boto3.client("s3", region_name="us-east-1").put_public_access_block(
        Bucket=name, PublicAccessBlockConfiguration=ALL_ON
    )


def by_resource(records):
    return {r.resource.rsplit(":::", 1)[-1]: r for r in records}


# ---- S3-07 public access block ------------------------------------------------------------


def test_s3_07_fails_for_a_bucket_with_no_public_access_block(ctx):
    make_bucket("bucket-open")
    records = by_resource(public_access_block.run(ctx))
    assert records["bucket-open"].status is Status.FAIL
    assert records["bucket-open"].evidence["BlockPublicAcls"] is False


def test_s3_07_passes_when_account_and_bucket_block_everything(ctx):
    make_bucket("bucket-locked")
    block_public_access("bucket-locked")
    boto3.client("s3control", region_name="us-east-1").put_public_access_block(
        AccountId=ctx.account_id, PublicAccessBlockConfiguration=ALL_ON
    )
    records = public_access_block.run(ctx)
    assert [r.status for r in records] == [Status.PASS, Status.PASS]


def test_s3_07_every_bucket_is_its_own_result(ctx):
    make_bucket("bucket-locked")
    block_public_access("bucket-locked")
    make_bucket("bucket-open")
    records = by_resource(public_access_block.run(ctx))
    assert records["bucket-locked"].status is Status.PASS
    assert records["bucket-open"].status is Status.FAIL
    assert len(records) == 3  # the account-level record plus two buckets


def test_s3_07_one_blocked_setting_is_enough_to_fail(ctx):
    make_bucket("bucket-partial")
    boto3.client("s3", region_name="us-east-1").put_public_access_block(
        Bucket="bucket-partial",
        PublicAccessBlockConfiguration={**ALL_ON, "BlockPublicPolicy": False},
    )
    records = by_resource(public_access_block.run(ctx))
    assert records["bucket-partial"].status is Status.FAIL
    assert records["bucket-partial"].evidence["BlockPublicPolicy"] is False


def test_s3_07_an_unreadable_bucket_is_an_error_and_does_not_hide_the_others(ctx, monkeypatch):
    make_bucket("bucket-a")
    make_bucket("bucket-b")
    real_client = ctx.session.client

    def client(name, *a, **k):
        c = real_client(name, *a, **k)
        if name == "s3":
            original = c.get_public_access_block

            def flaky(Bucket):
                if Bucket == "bucket-a":
                    raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetPublicAccessBlock")
                return original(Bucket=Bucket)

            c.get_public_access_block = flaky
        return c

    monkeypatch.setattr(ctx.session, "client", client)
    records = by_resource(public_access_block.run(ctx))
    assert records["bucket-a"].status is Status.ERROR
    assert records["bucket-a"].evidence == {"error": "AccessDenied"}
    assert records["bucket-b"].status is Status.FAIL  # still checked


# ---- S3-08 default encryption -------------------------------------------------------------


def test_s3_08_fails_when_the_bucket_has_no_default_encryption(ctx):
    make_bucket("bucket-plain")  # moto starts with no encryption: the failing input
    [record] = default_encryption.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"encryption": None}


def test_s3_08_passes_and_records_the_algorithm(ctx):
    make_bucket("bucket-sse")
    boto3.client("s3", region_name="us-east-1").put_bucket_encryption(
        Bucket="bucket-sse",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    [record] = default_encryption.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence == {"encryption": ["AES256"]}


def test_s3_08_with_no_buckets_still_leaves_evidence(ctx):
    [record] = default_encryption.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence == {"buckets_found": 0}


def test_s3_08_each_bucket_is_its_own_result(ctx):
    make_bucket("bucket-one")
    make_bucket("bucket-two")
    assert len(default_encryption.run(ctx)) == 2
