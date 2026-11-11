"""Importing a module here registers its checks. Add new modules to the list below."""

from scanner.checks import cloudtrail, config, iam, s3, vpc  # noqa: F401
