"""Rows from a mail gateway or a firewall say what was done with the step.

A plain log is not an alert: "delivered" or "accept" means the step was seen
and let through. Only "blocked" settles a prevention expectation.
"""

from unittest.mock import Mock

import pytest
from src.services.expectation_service import SplunkESExpectationService
from src.services.query_writer import QueryWriter, TemplateStore, index_clause
from src.services.spl_validator import SplunkESQueryRefusedError
from src.services.step_matching import (
    KEY_DISPOSITION,
    KEY_SOURCE,
    extract_disposition,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ({"action": "Drop"}, "blocked"),
        ({"final_action": "quarantine"}, "blocked"),
        ({"action": "blocked"}, "blocked"),
        ({"action": "Detect"}, "flagged"),
        ({"action": "Accept"}, "allowed"),
        ({"final_action": "delivered"}, "allowed"),
        ({"action": ["allowed", "blocked"]}, "allowed"),  # first recognised value
        ({"action": "something else"}, None),
        ({"rule_name": "no action field"}, None),
    ],
)
def test_extract_disposition(raw, expected):
    """The verdict words of the usual gateway logs."""
    assert extract_disposition(raw) == expected  # noqa: S101


def _service(log_sourcetypes="cp_log,pps_*"):
    service = SplunkESExpectationService.__new__(SplunkESExpectationService)
    service.config = Mock()
    service.config.splunk_es.log_sourcetypes = log_sourcetypes
    return service


def _row(sourcetype, disposition=None):
    row = {KEY_SOURCE: {"sourcetype": sourcetype}}
    if disposition:
        row[KEY_DISPOSITION] = disposition
    return row


@pytest.mark.parametrize(
    "sourcetype,disposition,kind,expected",
    [
        # detection: an alert counts whatever its action says
        ("XmlWinEventLog", None, "detection", None),
        ("XmlWinEventLog", "allowed", "detection", None),
        # detection: a plain log only counts when it blocked or flagged
        ("cp_log", "blocked", "detection", None),
        ("cp_log", "flagged", "detection", None),
        ("cp_log", "allowed", "detection", "seen_not_flagged"),
        ("pps_messagelog", None, "detection", "seen_not_flagged"),
        # prevention: only "blocked" settles it
        ("cp_log", "blocked", "prevention", None),
        ("cp_log", "allowed", "prevention", "not_blocked"),
        ("XmlWinEventLog", "flagged", "prevention", "not_blocked"),
        ("XmlWinEventLog", None, "prevention", "no_verdict_in_logs"),
    ],
)
def test_row_refusal(sourcetype, disposition, kind, expected):
    """Whether a row tied to the step settles the expectation."""
    row = _row(sourcetype, disposition)
    assert _service()._row_refusal(row, kind) == expected  # noqa: S101


def test_several_indexes_in_one_search():
    """'main, email' becomes one search over both; a bad name is refused."""
    assert index_clause(["main", "email"]) == "main OR index=email"  # noqa: S101
    writer = QueryWriter(TemplateStore(), index="main, email")
    assert writer.indexes == ["main", "email"]  # noqa: S101
    with pytest.raises(SplunkESQueryRefusedError):
        QueryWriter(TemplateStore(), index="main, bad index")
    with pytest.raises(SplunkESQueryRefusedError):
        QueryWriter(TemplateStore(), index=" , ")
