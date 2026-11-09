import boto3
import pytest
from moto import mock_aws
from moto.core import DEFAULT_ACCOUNT_ID
from moto.iam.models import iam_backends

from scanner.models import Context


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    """Fake credentials so a test can never touch a real account."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def ctx():
    """A scanner Context pointed at moto's fake AWS (account 123456789012)."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        yield Context(session=session, account_id=DEFAULT_ACCOUNT_ID, region="us-east-1")


@pytest.fixture
def iam_backend(ctx):
    """moto's IAM backend, for setting up states the public API cannot create."""
    return iam_backends[DEFAULT_ACCOUNT_ID]["global"]
