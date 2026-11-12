"""The shapes every check shares. Keep these stable: they are the evidence format."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

# Pin one CIS benchmark version and say so in the README. Verify every CIS
# number in scanner/checks/ against this version before you publish.
CIS_VERSION = "CIS AWS Foundations Benchmark v7.1.0"


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"  # the check could not run (for example, a permissions problem)


@dataclass(frozen=True)
class Controls:
    """The framework references a check is evidence for."""

    cis: str
    nist_800_53_r5: str
    iso_27001_2022: str
    soc2: str


@dataclass(frozen=True)
class Finding:
    """What a check function returns: one verdict about one resource."""

    status: Status
    resource: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Context:
    """What a check receives: a boto3 session plus who and where we are scanning."""

    session: Any  # boto3.Session
    account_id: str
    region: str


@dataclass(frozen=True)
class Evidence:
    """One evidence record. This is what gets written to disk."""

    check_id: str
    title: str
    status: Status
    resource: str
    region: str
    account_id: str
    timestamp: str
    controls: Controls
    evidence: dict[str, Any]
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        record = asdict(self)
        record["status"] = self.status.value
        return record

def worst_status(records: Iterable[Evidence]) -> Status:
    """The one status that sums up a group of records: ERROR beats FAIL beats PASS."""
    statuses = {r.status for r in records}
    if Status.ERROR in statuses:
        return Status.ERROR
    if Status.FAIL in statuses:
        return Status.FAIL
    return Status.PASS
