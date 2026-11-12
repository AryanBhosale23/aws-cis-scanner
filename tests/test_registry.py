import scanner.checks  # noqa: F401 - importing registers the checks
from scanner.checks.base import REGISTRY
from scanner.models import CIS_VERSION


def test_there_are_twenty_checks():
    assert len(REGISTRY) == 20


def test_no_check_has_leftover_todo_text():
    for check in REGISTRY.values():
        text = f"{check.title} {check.remediation} {check.controls}"
        assert "TODO" not in text, check.check_id


def test_every_check_cites_the_pinned_cis_version():
    for check in REGISTRY.values():
        assert check.controls.cis.startswith(f"{CIS_VERSION}, "), check.check_id
