"""Copy one evidence file to examples/ with the real account number swapped for a fake one.

Usage:    python scripts/make_example.py <evidence file> <new file>
Example:  python scripts/make_example.py evidence/RUN/S3-07.json examples/S3-07-before.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

FAKE_ACCOUNT = "123456789012"  # the account number AWS uses in its own documentation


def mask_file(source: Path, target: Path) -> None:
    text = source.read_text(encoding="utf-8")
    records = json.loads(text)
    real_accounts = {r["account_id"] for r in records} - {FAKE_ACCOUNT}
    for real in real_accounts:
        text = text.replace(real, FAKE_ACCOUNT)
    for real in real_accounts:
        if real in text:
            raise SystemExit(f"Refusing to write: {real} is still in the output")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    print(f"Wrote {target} (account number replaced by {FAKE_ACCOUNT})")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    mask_file(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    main()
