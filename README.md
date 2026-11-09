# aws-cis-scanner

A read-only Python/boto3 command-line scanner that checks an AWS account against CIS-based controls
and writes one structured evidence record per result, mapped to NIST 800-53 Rev 5, ISO 27001:2022 and SOC 2.

> Work in progress. Scenario: you are the first compliance engineer at a 50-person SaaS company
> preparing for a SOC 2 and ISO 27001 audit, replacing screenshot-based evidence with one command.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
scanner run --profile audit
pytest && ruff check .
```

Use a read-only identity (AWS managed policies `SecurityAudit` and `ViewOnlyAccess`). Never your admin user.

## Evidence record

One JSON file per check in `evidence/<run time>/`. See `scanner/models.py` for the exact fields.

## How to add a check

1. Add a function to the right file in `scanner/checks/` and decorate it with `@check(...)`.
2. Give it its control IDs and a remediation line.
3. Return one `Finding` per resource.
4. Write a passing and a failing test in `tests/`.

## Limits and sources

TODO: fill in as you build (what it does not check; scale-up ideas; CIS version and sources).
