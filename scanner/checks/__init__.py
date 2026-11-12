"""Importing a module here registers its checks. Add new modules to the list below."""

from scanner.checks import cloudtrail, config, iam, kms, s3, vpc  # noqa: F401
