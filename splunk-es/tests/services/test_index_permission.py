"""The index check must notice an index the account's roles may not search.

Found on a real Splunk Enterprise: a search-only account gets HTTP 200 for an
index that exists, and a search of it returns zero rows with no error when the
account's roles do not allow that index. Without this check the empty answer
would be scored as a missed detection.
"""

from unittest.mock import Mock

import pytest
from src.services.client_api import SplunkESClientAPI
from src.services.exception import SplunkESIndexNotFoundError
from tests.services.fixtures.factories import create_test_config


def _answer(status, content=None):
    response = Mock()
    response.status_code = status
    response.json.return_value = {"entry": [{"content": content or {}}]}
    return response


def _client(roles, role_content, index="main", context_status=200, role_status=200):
    client = SplunkESClientAPI(config=create_test_config())
    client.alerts_index = index
    client._index_checked_at = None

    def get(url, **_kwargs):
        if url.endswith(f"/services/data/indexes/{index}"):
            return _answer(200, {})
        if url.endswith("/services/authentication/current-context"):
            return _answer(context_status, {"roles": roles})
        if "/services/authorization/roles/" in url:
            return _answer(role_status, role_content)
        return _answer(404)

    client.session = Mock()
    client.session.get.side_effect = get
    return client


@pytest.mark.parametrize(
    "index,pattern,expected",
    [
        ("main", "main", True),
        ("main", "*", True),
        ("main", "ma*", True),
        ("Main", "main", True),
        ("main", "telemetry", False),
        ("_internal", "*", False),  # '*' does not cover internal indexes
        ("_internal", "_*", True),
    ],
)
def test_index_pattern(index, pattern, expected):
    """Splunk's wildcard rule for role index lists."""
    assert (  # noqa: S101
        SplunkESClientAPI._index_pattern_matches(index, pattern) is expected
    )


def test_allowed_index_passes():
    """An index the role lists is accepted."""
    client = _client(["reader"], {"srchIndexesAllowed": ["main", "telemetry"]})
    client.ensure_index_available()
    assert client._index_checked_at is not None  # noqa: S101


def test_index_allowed_through_an_inherited_role_passes():
    """Index lists inherited from other roles count too."""
    client = _client(
        ["reader"],
        {"srchIndexesAllowed": [], "imported_srchIndexesAllowed": ["*"]},
    )
    client.ensure_index_available()


def test_index_the_role_does_not_list_is_refused():
    """Exists, but not searchable by this account: not an empty index."""
    client = _client(["reader"], {"srchIndexesAllowed": ["telemetry"]})
    with pytest.raises(SplunkESIndexNotFoundError):
        client.ensure_index_available()
    assert client._index_checked_at is None  # noqa: S101


def test_disallowed_index_is_refused_even_when_a_wildcard_allows_it():
    """A disallow entry wins over an allow entry."""
    client = _client(
        ["reader"],
        {"srchIndexesAllowed": ["*"], "srchIndexesDisallowed": ["main"]},
    )
    with pytest.raises(SplunkESIndexNotFoundError):
        client.ensure_index_available()


@pytest.mark.parametrize("context_status,role_status", [(403, 200), (200, 403)])
def test_when_splunk_will_not_say_the_search_goes_ahead(context_status, role_status):
    """No answer about the roles is not a refusal."""
    client = _client(
        ["reader"],
        {"srchIndexesAllowed": ["telemetry"]},
        context_status=context_status,
        role_status=role_status,
    )
    client.ensure_index_available()
    assert client._index_checked_at is not None  # noqa: S101
