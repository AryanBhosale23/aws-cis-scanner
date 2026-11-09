"""Writes evidence records to disk: one JSON file per check, in a folder named by run time."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

from scanner.models import Evidence


def mask_account(account_id: str) -> str:
    """123456789012 -> ************9012 (for console output and published samples)."""
    return "*" * (len(account_id) - 4) + account_id[-4:]


def write_evidence(results: list[Evidence], output_dir: Path) -> Path:
    run_dir = output_dir / datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
    run_dir.mkdir(parents=True, exist_ok=False)
    by_check: dict[str, list[Evidence]] = defaultdict(list)
    for r in results:
        by_check[r.check_id].append(r)
    for check_id, records in by_check.items():
        path = run_dir / f"{check_id}.json"
        path.write_text(json.dumps([r.to_dict() for r in records], indent=2) + "\n")
    return run_dir
