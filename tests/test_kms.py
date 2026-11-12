import boto3

from scanner.checks.kms import key_rotation_enabled
from scanner.models import Status


def kms_client():
    return boto3.client("kms", region_name="us-east-1")


def make_key(*, rotation=False, **kwargs):
    """Create a customer-managed key in the fake AWS and return its ID."""
    kms = kms_client()
    key_id = kms.create_key(**kwargs)["KeyMetadata"]["KeyId"]
    if rotation:
        kms.enable_key_rotation(KeyId=key_id)
    return key_id


def by_key(records):
    return {r.resource.rsplit("/", 1)[-1]: r for r in records}


# ---- KMS-19 key rotation ------------------------------------------------------------------


def test_kms_19_fails_when_rotation_is_off(ctx):
    make_key(rotation=False)
    [record] = key_rotation_enabled.run(ctx)
    assert record.status is Status.FAIL
    assert record.evidence == {"rotation_enabled": False}


def test_kms_19_passes_when_rotation_is_on(ctx):
    make_key(rotation=True)
    [record] = key_rotation_enabled.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence == {"rotation_enabled": True}


def test_kms_19_every_key_is_its_own_result(ctx):
    rotated = make_key(rotation=True)
    plain = make_key(rotation=False)
    records = by_key(key_rotation_enabled.run(ctx))
    assert records[rotated].status is Status.PASS
    assert records[plain].status is Status.FAIL


def test_kms_19_ignores_asymmetric_keys(ctx):
    make_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")  # cannot rotate, so not judged
    [record] = key_rotation_enabled.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence == {"customer_keys_found": 0}


def test_kms_19_ignores_disabled_keys(ctx):
    key_id = make_key(rotation=False)
    kms_client().disable_key(KeyId=key_id)
    [record] = key_rotation_enabled.run(ctx)
    assert record.evidence == {"customer_keys_found": 0}


def test_kms_19_with_no_keys_still_leaves_evidence(ctx):
    [record] = key_rotation_enabled.run(ctx)
    assert record.status is Status.PASS
    assert record.evidence == {"customer_keys_found": 0}