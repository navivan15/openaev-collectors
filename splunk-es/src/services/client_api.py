"""Splunk ES API client for making HTTP requests with proper error handling."""

import logging
import string
import time
from datetime import timedelta
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import quote

import requests  # type: ignore[import-untyped]
from requests.exceptions import (  # type: ignore[import-untyped]
    ConnectionError,
    RequestException,
    Timeout,
)

from ..models.configs.config_loader import ConfigLoader
from .exception import (
    SplunkESAPIError,
    SplunkESAuthenticationError,
    SplunkESIndexNotFoundError,
    SplunkESNetworkError,
    SplunkESQueryError,
    SplunkESServiceError,
    SplunkESSessionError,
    SplunkESValidationError,
)
from .models import SplunkESAlert, SplunkESResponse, SplunkESSearchCriteria
from .spl_validator import validate_spl
from .step_matching import markers_from_parent_process
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[SplunkESClientAPI]"


DEFAULT_TIME_WINDOW_HOURS = 1
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
# How long a successful "the alerts index exists" check is trusted.
INDEX_CHECK_TTL_SECONDS = 300

# The IP + implant branch is the original (legacy) filter. {step_marker_clause}
# adds an OR branch that fetches any event carrying the step marker (the inject
# ID) even when it has no IP fields - e.g. an EDR process event. It renders to
# an empty string when the step has no marker, leaving the legacy filter as is.
DEFAULT_QUERY_TEMPLATE = (
    "index={alerts_index} {sourcetype_filter} "
    "((("
    "(src_ip IN ({source_ips}) OR src IN ({source_ips}) OR source_ip IN ({source_ips}) OR client_ip IN ({source_ips})) "
    "(dst_ip IN ({target_ips}) OR dest IN ({target_ips}) OR dest_ip IN ({target_ips}) "
    "OR destination_ip IN ({target_ips}) OR server_ip IN ({target_ips})) "
    "(url_path IN ({implant_urls}) OR url IN ({implant_urls}) OR path IN ({implant_urls}) "
    "OR query IN ({implant_urls}) OR process_name IN ({implant_names}) "
    "OR parent_process_name IN ({implant_names}))"
    ")){step_marker_clause}) "
    "earliest={start_date} latest={end_date} "
    "| table _time, src_ip, src, source_ip, client_ip, dst_ip, dest, dest_ip, "
    "destination_ip, server_ip, signature, rule_name, event_type, severity, "
    "url_path, url, path, query, process_name, parent_process_name, "
    "process, command_line, CommandLine, parent_process, file_name, file_path, "
    "TargetFilename, dest_host, dest_nt_host, hostname, ComputerName, dvc, "
    "_raw | sort -_time"
)

ALLOWED_PLACEHOLDERS = {
    "alerts_index",
    "source_ips",
    "target_ips",
    "implant_urls",
    "implant_names",
    "ip_conditions",
    "process_conditions",
    "time_window",
    "start_date",
    "end_date",
    "step_marker_clause",
    "sourcetype_filter",
}


class _SafeFormatter(string.Formatter):
    """Restricted formatter that prevents attribute/index access in format strings."""

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> tuple:
        """Override to block attribute traversal (e.g., {value.__class__})."""
        if "." in field_name or "[" in field_name:
            raise ValueError(
                f"Attribute/index access not allowed in query template: '{field_name}'"
            )
        return super().get_field(field_name, args, kwargs)


_safe_formatter = _SafeFormatter()


class SplunkESClientAPI:
    """Splunk ES API client for fetching alerts and data."""

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the Splunk ES API client.

        Args:
            config: Configuration loader instance for API client settings.

        Raises:
            SplunkESValidationError: If config is None or has invalid structure.
            SplunkESSessionError: If session creation fails.

        """
        if config is None:
            raise SplunkESValidationError("Config is required for API client")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.base_url = str(self.config.splunk_es.base_url).rstrip("/")
            self.username = self.config.splunk_es.username
            self.password = (
                self.config.splunk_es.password.get_secret_value()
                if self.config.splunk_es.password
                else None
            )
            self.token = (
                self.config.splunk_es.token.get_secret_value()
                if getattr(self.config.splunk_es, "token", None)
                else None
            )
            self.verify_ssl = getattr(self.config.splunk_es, "verify_ssl", True)
            self.alerts_index = self.config.splunk_es.alerts_index or "_notable"
            self.offset = self.config.splunk_es.offset.total_seconds()
            self.max_retry = self.config.splunk_es.max_retry
        except AttributeError as e:
            raise SplunkESValidationError(f"Invalid config structure: {e}") from e

        if (
            hasattr(self.config.splunk_es, "time_window")
            and self.config.splunk_es.time_window
        ):
            self.time_window = self.config.splunk_es.time_window
        else:
            self.time_window = timedelta(hours=DEFAULT_TIME_WINDOW_HOURS)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default {DEFAULT_TIME_WINDOW_HOURS} hour"
            )

        self.query_template = self.config.splunk_es.query_template
        if self.query_template:
            self._validate_template_placeholders(self.query_template)
            self.logger.info(
                f"{LOG_PREFIX} Using custom query template from configuration"
            )
        else:
            self.query_template = DEFAULT_QUERY_TEMPLATE
            self.logger.debug(
                f"{LOG_PREFIX} No custom query template configured, using default"
            )

        try:
            self.session = self._create_session()
            self.parent_process_parser = ParentProcessParser()
        except Exception as e:
            raise SplunkESSessionError(f"Failed to create HTTP session: {e}") from e

        self._index_checked_at: float | None = None
        # Number of searches actually sent to Splunk by this client.
        self.search_count = 0
        raw_sourcetypes = getattr(self.config.splunk_es, "sourcetypes", "*")
        self.sourcetypes = [
            s.strip()
            for s in str(raw_sourcetypes or "*").split(",")
            if s.strip()
        ] or ["*"]

        self.logger.info(f"{LOG_PREFIX} Splunk ES API client initialized successfully")

    def _validate_template_placeholders(self, template: str) -> None:
        """Validate that a custom query template only uses allowed placeholders.

        Args:
            template: The query template string to validate.

        Raises:
            SplunkESValidationError: If unknown placeholders are found.

        """
        formatter = string.Formatter()
        used_placeholders = {
            field_name
            for _, field_name, _, _ in formatter.parse(template)
            if field_name is not None
        }
        unknown = used_placeholders - ALLOWED_PLACEHOLDERS
        if unknown:
            raise SplunkESValidationError(
                f"Unknown placeholders in query template: {unknown}. "
                f"Allowed: {sorted(ALLOWED_PLACEHOLDERS)}"
            )

    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper authentication.

        Returns:
            Configured requests.Session with authentication.

        Raises:
            SplunkESValidationError: If credentials are missing.
            SplunkESSessionError: If session configuration fails.

        """
        use_token = bool(self.token)
        if not use_token and (not self.username or not self.password):
            raise SplunkESValidationError(
                "Provide either SPLUNKES_TOKEN (bearer) or both "
                "SPLUNKES_USERNAME and SPLUNKES_PASSWORD for session creation"
            )

        try:
            session = requests.Session()
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
            if use_token:
                headers["Authorization"] = f"Bearer {self.token}"
                self.logger.info(f"{LOG_PREFIX} Using bearer-token authentication")
            else:
                session.auth = (self.username, self.password)
                self.logger.info(f"{LOG_PREFIX} Using basic authentication")
            session.headers.update(headers)
            session.timeout = REQUEST_TIMEOUT_SECONDS
            session.verify = self.verify_ssl
            if not self.verify_ssl:
                self.logger.warning(
                    f"{LOG_PREFIX} TLS certificate verification is DISABLED "
                    f"(SPLUNKES_VERIFY_SSL=false). Use only for trusted lab instances."
                )
                # Silence the noisy urllib3 warning we opted into deliberately.
                try:
                    import urllib3

                    urllib3.disable_warnings(
                        urllib3.exceptions.InsecureRequestWarning
                    )
                except Exception:  # pragma: no cover - best effort only
                    pass
            return session
        except Exception as e:
            raise SplunkESSessionError(f"Failed to configure session: {e}") from e

    def ensure_index_available(self) -> None:
        """Check that the alerts index exists before trusting an empty search.

        A search against a missing (or unreadable) index returns zero rows,
        which would otherwise be scored as a missed detection. Wildcard or
        multi-index values are not checked. A positive answer is cached for
        INDEX_CHECK_TTL_SECONDS.

        Raises:
            SplunkESIndexNotFoundError: Index missing / not visible (HTTP 404).
            SplunkESAuthenticationError: Credentials rejected (HTTP 401).
            SplunkESNetworkError: Splunk unreachable.

        """
        index = (self.alerts_index or "").strip()
        if not index or any(c in index for c in '*, ()="'):
            return
        now = time.monotonic()
        if (
            self._index_checked_at is not None
            and now - self._index_checked_at < INDEX_CHECK_TTL_SECONDS
        ):
            return

        url = f"{self.base_url}/services/data/indexes/{quote(index, safe='')}"
        try:
            response = self.session.get(
                url, params={"output_mode": "json"}, timeout=REQUEST_TIMEOUT_SECONDS
            )
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(
                f"Splunk unreachable while checking index '{index}': {e}"
            ) from e
        except RequestException as e:
            raise SplunkESAPIError(
                f"HTTP error while checking index '{index}': {e}"
            ) from e

        if response.status_code == 401:
            raise SplunkESAuthenticationError("Authentication with Splunk ES failed")
        if response.status_code == 404:
            raise SplunkESIndexNotFoundError(
                f"Splunk index '{index}' does not exist or this account cannot read it"
            )
        if response.status_code == 200:
            # The index exists. That does not mean this account may search it:
            # a search of an index the account's roles do not allow returns
            # zero rows and no error, exactly like an empty index.
            if self._index_searchable(index) is False:
                raise SplunkESIndexNotFoundError(
                    f"Splunk index '{index}' exists, but this account's roles "
                    f"do not allow searching it"
                )
            self._index_checked_at = now
            return
        # 403 and others: we cannot verify, so let the search itself decide.
        self.logger.warning(
            f"{LOG_PREFIX} Could not verify index '{index}' "
            f"(HTTP {response.status_code}); continuing with the search"
        )

    @staticmethod
    def _index_pattern_matches(index: str, pattern: str) -> bool:
        """Splunk's own rule: '*' does not cover internal (underscore) indexes."""
        if index.startswith("_") and not pattern.startswith("_"):
            return False
        return fnmatchcase(index.lower(), pattern.lower())

    def _index_searchable(self, index: str) -> bool | None:
        """Whether this account's roles allow searching ``index``.

        Reads the account's own context and its roles (both readable by a
        search-only account). Returns None when Splunk does not let us tell,
        in which case the search goes ahead as before.
        """
        try:
            context = self.session.get(
                f"{self.base_url}/services/authentication/current-context",
                params={"output_mode": "json"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if context.status_code != 200:
                return None
            roles = context.json()["entry"][0]["content"]["roles"]
            if not isinstance(roles, list) or not roles:
                return None
            allowed: list[str] = []
            disallowed: list[str] = []
            for role in roles:
                answer = self.session.get(
                    f"{self.base_url}/services/authorization/roles/"
                    f"{quote(str(role), safe='')}",
                    params={"output_mode": "json"},
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
                if answer.status_code != 200:
                    return None
                content = answer.json()["entry"][0]["content"]
                for key in ("srchIndexesAllowed", "imported_srchIndexesAllowed"):
                    allowed += [str(v) for v in content.get(key) or []]
                for key in ("srchIndexesDisallowed", "imported_srchIndexesDisallowed"):
                    disallowed += [str(v) for v in content.get(key) or []]
        except (RequestException, ValueError, KeyError, IndexError, TypeError):
            return None
        if any(self._index_pattern_matches(index, p) for p in disallowed):
            return False
        return any(self._index_pattern_matches(index, p) for p in allowed)

    def fetch_signatures(
        self, search_signatures: list[dict[str, Any]], expectation_type: str
    ) -> list[SplunkESAlert]:
        """Fetch Splunk ES alerts based on search signatures.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If inputs are invalid.
            SplunkESAPIError: If API operations fail.

        """
        if not search_signatures:
            raise SplunkESValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise SplunkESValidationError(
                f"Invalid expectation_type: {expectation_type}. Splunk ES only supports 'detection'"
            )

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Fetching signatures for {expectation_type} expectation with {len(search_signatures)} signatures"
            )

            search_criteria = self._build_search_criteria(search_signatures)

            self.ensure_index_available()

            self.logger.debug(f"{LOG_PREFIX} Executing Splunk ES query with retry...")
            alerts = self._execute_splunk_query_with_retry(search_criteria)

            self.logger.info(
                f"{LOG_PREFIX} Fetched {len(alerts)} alerts from Splunk ES"
            )
            return alerts

        except SplunkESServiceError:
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SplunkESAPIError(f"Unexpected error fetching signatures: {e}") from e

    def _build_search_criteria(
        self, search_signatures: list[dict[str, str]]
    ) -> SplunkESSearchCriteria:
        """Build SplunkESSearchCriteria object from search signatures.

        Args:
            search_signatures: List of signature dictionaries.

        Returns:
            SplunkESSearchCriteria object.

        Raises:
            SplunkESValidationError: If signature format is invalid.

        """
        try:
            self.logger.debug(
                f"{LOG_PREFIX} Building search criteria from {len(search_signatures)} signatures"
            )

            source_ips = []
            target_ips = []
            parent_process_names = []
            start_date = None
            end_date = None

            for sig in search_signatures:
                if not isinstance(sig, dict) or "type" not in sig or "value" not in sig:
                    raise SplunkESValidationError(f"Invalid signature format: {sig}")

                sig_type = sig.get("type")
                sig_value = sig.get("value")
                self.logger.debug(
                    f"{LOG_PREFIX} Processing signature: {sig_type}={sig_value}"
                )

                if sig_type in ["source_ipv4_address", "source_ipv6_address"]:
                    source_ips.append(sig_value)
                elif sig_type in ["target_ipv4_address", "target_ipv6_address"]:
                    target_ips.append(sig_value)
                elif sig_type == "parent_process_name":
                    parent_process_names.append(sig_value)
                elif sig_type == "start_date":
                    start_date = sig_value
                elif sig_type == "end_date":
                    end_date = sig_value

            if not start_date and not end_date:
                self.logger.info(
                    f"{LOG_PREFIX} No date signatures provided, will use time_window in query: {self.time_window}"
                )

            criteria = SplunkESSearchCriteria(
                source_ips=source_ips,
                target_ips=target_ips,
                parent_process_names=parent_process_names,
                start_date=start_date,
                end_date=end_date,
            )

            self.logger.debug(
                f"{LOG_PREFIX} Built search criteria: source_ips={len(source_ips)}, target_ips={len(target_ips)}, "
                f"parent_process_names={len(parent_process_names)}, date_range={start_date} to {end_date}"
            )
            return criteria

        except SplunkESValidationError:
            raise
        except Exception as e:
            raise SplunkESValidationError(
                f"Failed to build search criteria: {e}"
            ) from e

    def _execute_splunk_query(
        self, search_criteria: SplunkESSearchCriteria, extend_end_seconds: int = 0
    ) -> list[SplunkESAlert]:
        """Execute Splunk ES query based on search criteria.

        Args:
            search_criteria: SplunkESSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If search criteria is invalid.
            SplunkESQueryError: If query execution fails.
            SplunkESAuthenticationError: If authentication fails.
            SplunkESAPIError: If API call fails.

        """
        if not search_criteria:
            raise SplunkESValidationError("search_criteria cannot be None")

        try:
            spl_query = self._build_spl_query(search_criteria, extend_end_seconds)
            return self.run_search(spl_query)

        except (
            SplunkESValidationError,
            SplunkESQueryError,
            SplunkESAuthenticationError,
            SplunkESAPIError,
            SplunkESNetworkError,
        ):
            raise
        except Exception as e:
            raise SplunkESQueryError(f"Unexpected error executing query: {e}") from e

    def run_search(self, spl_query: str) -> list[SplunkESAlert]:
        """Validate one SPL search, send it as a oneshot job and parse the rows.

        The validator runs first: a refused search is never sent.

        Raises:
            SplunkESQueryRefusedError: The search is not allowed (nothing sent).
            SplunkESAuthenticationError: Credentials rejected.
            SplunkESNetworkError: Splunk unreachable.
            SplunkESAPIError / SplunkESQueryError: The search failed.

        """
        validate_spl(spl_query)

        try:
            self.logger.debug(f"{LOG_PREFIX} Executing SPL query: {spl_query}")

            endpoint = f"{self.base_url}/services/search/jobs"

            params = {
                "search": f"search {spl_query}",
                "exec_mode": "oneshot",
                "output_mode": "json",
                "count": "0",
            }

            self.search_count += 1
            response = self.session.post(
                endpoint, data=params, timeout=REQUEST_TIMEOUT_SECONDS
            )

            if response.status_code == 401:
                raise SplunkESAuthenticationError(
                    "Authentication with Splunk ES failed"
                )
            elif response.status_code != 200:
                raise SplunkESAPIError(
                    f"Splunk ES API returned status {response.status_code}: {response.text}"
                )

            response_data = response.json()
            search_errors = [
                str(m.get("text", ""))
                for m in (response_data.get("messages") or [])
                if isinstance(m, dict)
                and str(m.get("type", "")).upper() in ("ERROR", "FATAL")
            ]
            if search_errors and not response_data.get("results"):
                # No rows AND Splunk says the search failed: an empty answer
                # here is not evidence of a miss.
                raise SplunkESQueryError(
                    f"Splunk search reported errors: {'; '.join(search_errors)}"
                )
            splunk_response = SplunkESResponse.from_raw_response(response_data)

            self.logger.info(
                f"{LOG_PREFIX} Retrieved {len(splunk_response.results)} alerts from Splunk ES"
            )
            return splunk_response.results

        except (
            SplunkESValidationError,
            SplunkESQueryError,
            SplunkESAuthenticationError,
            SplunkESAPIError,
        ):
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during query: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed during query: {e}") from e
        except Exception as e:
            raise SplunkESQueryError(f"Unexpected error executing query: {e}") from e

    def _execute_splunk_query_with_retry(
        self, search_criteria: SplunkESSearchCriteria
    ) -> list[SplunkESAlert]:
        """Execute Splunk ES query with retry mechanism.

        Args:
            search_criteria: SplunkESSearchCriteria object with search parameters.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If search criteria is invalid.
            SplunkESQueryError: If query execution fails after all retries.
            SplunkESAuthenticationError: If authentication fails.
            SplunkESAPIError: If API call fails after all retries.

        """
        if not search_criteria:
            raise SplunkESValidationError("search_criteria cannot be None")

        self.logger.info(
            f"{LOG_PREFIX} Starting Splunk ES fetch with {self.offset}s offset and {self.max_retry} max retries"
        )

        last_exception = None

        for attempt in range(self.max_retry + 1):
            try:
                self.logger.debug(
                    f"{LOG_PREFIX} Splunk ES query attempt {attempt + 1} of {self.max_retry + 1}"
                )

                if attempt > 0:
                    sleep_time = int(self.offset)
                    self.logger.debug(
                        f"{LOG_PREFIX} Waiting {sleep_time}s before retry {attempt + 1}..."
                    )
                    time.sleep(sleep_time)
                    extend_seconds = sleep_time * attempt
                else:
                    extend_seconds = 0

                alerts = self._execute_splunk_query(search_criteria, extend_seconds)

                if alerts:
                    self.logger.info(
                        f"{LOG_PREFIX} Splunk ES attempt {attempt + 1}: Found {len(alerts)} alerts - success!"
                    )
                    return alerts
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} Splunk ES attempt {attempt + 1}: No alerts found"
                    )
                    if attempt == self.max_retry:
                        self.logger.warning(
                            f"{LOG_PREFIX} No alerts found after all retry attempts"
                        )
                        return []

            except (SplunkESAuthenticationError, SplunkESValidationError) as e:
                raise e
            except (
                SplunkESAPIError,
                SplunkESNetworkError,
                SplunkESQueryError,
                ConnectionError,
                Timeout,
                RequestException,
            ) as e:
                last_exception = e
                self.logger.warning(
                    f"{LOG_PREFIX} Splunk ES attempt {attempt + 1} failed: {e}"
                )
                if attempt == self.max_retry:
                    break

        if last_exception:
            raise SplunkESAPIError(
                f"All Splunk ES fetch attempts failed. Last error: {last_exception}"
            ) from last_exception
        else:
            self.logger.warning(
                f"{LOG_PREFIX} No alerts found after all retry attempts"
            )
            return []

    def fetch_with_retry(
        self,
        search_signatures: list[dict[str, Any]],
        expectation_type: str,
        max_retries: int | None = None,
        offset_seconds: int | None = None,
    ) -> list[SplunkESAlert]:
        """Fetch Splunk ES alerts with retry mechanism.

        Args:
            search_signatures: List of signature dictionaries.
            expectation_type: Type of expectation for the fetched data.
            max_retries: Maximum number of retry attempts (defaults to config value).
            offset_seconds: Seconds to wait between retries (defaults to config value).

        Returns:
            List of SplunkESAlert objects.

        Raises:
            SplunkESValidationError: If inputs are invalid.
            SplunkESAPIError: If all retry attempts fail.

        """
        if not search_signatures:
            raise SplunkESValidationError("search_signatures cannot be empty")
        if expectation_type not in {"detection"}:
            raise SplunkESValidationError(
                f"Invalid expectation_type: {expectation_type}. Splunk ES only supports 'detection'"
            )

        if max_retries is None:
            max_retries = self.max_retry
        if offset_seconds is None:
            offset_seconds = int(self.offset)

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting fetch with retry: max_retries={max_retries}, offset={offset_seconds}s"
            )

            search_criteria = self._build_search_criteria(search_signatures)

            self.ensure_index_available()

            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    self.logger.debug(
                        f"{LOG_PREFIX} Fetch attempt {attempt + 1} of {max_retries + 1}"
                    )

                    if attempt > 0:
                        self.logger.debug(
                            f"{LOG_PREFIX} Waiting {offset_seconds}s before retry {attempt + 1}..."
                        )
                        time.sleep(offset_seconds)
                        extend_seconds = offset_seconds * attempt
                    else:
                        extend_seconds = 0

                    alerts = self._execute_splunk_query(search_criteria, extend_seconds)

                    if alerts:
                        self.logger.info(
                            f"{LOG_PREFIX} Fetch attempt {attempt + 1}: Found {len(alerts)} alerts - success!"
                        )
                        return alerts
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Fetch attempt {attempt + 1}: No alerts found"
                        )

                except (SplunkESAuthenticationError, SplunkESValidationError) as e:
                    raise e
                except (
                    SplunkESAPIError,
                    SplunkESNetworkError,
                    SplunkESQueryError,
                    ConnectionError,
                    Timeout,
                    RequestException,
                ) as e:
                    last_exception = e
                    self.logger.warning(
                        f"{LOG_PREFIX} Fetch attempt {attempt + 1} failed: {e}"
                    )

            if last_exception:
                raise SplunkESAPIError(
                    f"All fetch attempts failed. Last error: {last_exception}"
                ) from last_exception
            else:
                self.logger.warning(
                    f"{LOG_PREFIX} No alerts found after all retry attempts"
                )
                return []

        except SplunkESServiceError:
            raise
        except (ConnectionError, Timeout) as e:
            raise SplunkESNetworkError(f"Network error during fetch: {e}") from e
        except RequestException as e:
            raise SplunkESAPIError(f"HTTP request failed: {e}") from e
        except Exception as e:
            raise SplunkESAPIError(f"Unexpected error in fetch_with_retry: {e}") from e

    def _build_spl_query(
        self, search_criteria: SplunkESSearchCriteria, extend_end_seconds: int = 0
    ) -> str:
        """Build SPL query from search criteria.

        If a custom query template is configured, resolves placeholders in it.
        Otherwise, uses the built-in query construction logic.

        Args:
            search_criteria: SplunkESSearchCriteria object.
            extend_end_seconds: Optional seconds to extend the end_date for retries.

        Returns:
            SPL query string.

        Raises:
            SplunkESValidationError: If criteria is invalid.

        """
        try:
            ip_conditions_str = self._build_ip_conditions(search_criteria)
            process_conditions_str = self._build_process_conditions(search_criteria)
            source_ips_str = self._build_ip_list(search_criteria.source_ips)
            target_ips_str = self._build_ip_list(search_criteria.target_ips)
            implant_urls_str = self._build_implant_url_list(
                search_criteria.parent_process_names or []
            )
            implant_names_str = self._build_implant_name_list(
                search_criteria.parent_process_names or []
            )
            step_marker_clause = self._build_step_marker_clause(
                search_criteria.parent_process_names or []
            )
            sourcetype_filter = self._build_sourcetype_filter(self.sourcetypes)
            time_window_seconds = int(self.time_window.total_seconds())
            earliest_seconds = time_window_seconds + extend_end_seconds

            # Resolve start_date/end_date: use signature values if available, else relative time
            start_date_str = (
                search_criteria.start_date
                if search_criteria.start_date
                else f"-{earliest_seconds}s"
            )
            end_date_str = (
                search_criteria.end_date if search_criteria.end_date else "now"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Using time range: earliest={start_date_str}, latest={end_date_str} "
                f"(base: {time_window_seconds}s + extend: {extend_end_seconds}s)"
            )

            full_query = _safe_formatter.format(
                self.query_template,
                alerts_index=self.alerts_index or "*",
                source_ips=source_ips_str,
                target_ips=target_ips_str,
                implant_urls=implant_urls_str,
                implant_names=implant_names_str,
                ip_conditions=ip_conditions_str,
                process_conditions=process_conditions_str,
                time_window=earliest_seconds,
                start_date=start_date_str,
                end_date=end_date_str,
                step_marker_clause=step_marker_clause,
                sourcetype_filter=sourcetype_filter,
            )

            # Normalize whitespace: collapse runs of spaces caused by empty placeholders.
            # This is safe because SPL tokens are never whitespace-sensitive.
            full_query = " ".join(full_query.split())

            if "| table" not in full_query:
                self.logger.error(
                    f"{LOG_PREFIX} Query template does not contain '| table' pipe. "
                    "Alert parsing will fail without proper field extraction."
                )

            self.logger.debug(f"{LOG_PREFIX} Built SPL query: {full_query}")
            return full_query

        except (KeyError, ValueError) as e:
            raise SplunkESValidationError(f"Invalid query template: {e}") from e
        except Exception as e:
            raise SplunkESValidationError(f"Failed to build SPL query: {e}") from e

    def _build_ip_conditions(self, search_criteria: SplunkESSearchCriteria) -> str:
        """Build IP filter conditions from search criteria.

        Args:
            search_criteria: SplunkESSearchCriteria with source/target IPs.

        Returns:
            IP conditions string for SPL query, or empty string if no IPs.

        """
        ip_conditions = []

        src_fields = ["src_ip", "src", "source_ip", "client_ip"]
        for ip in search_criteria.source_ips:
            ip_conditions.extend([f"{field}={ip}" for field in src_fields])

        dst_fields = ["dst_ip", "dest", "dest_ip", "destination_ip", "server_ip"]
        for ip in search_criteria.target_ips:
            ip_conditions.extend([f"{field}={ip}" for field in dst_fields])

        if ip_conditions:
            return f"({' OR '.join(ip_conditions)})"
        return ""

    def _build_process_conditions(self, search_criteria: SplunkESSearchCriteria) -> str:
        """Build parent process / URL path conditions from search criteria.

        Args:
            search_criteria: SplunkESSearchCriteria with parent process names.

        Returns:
            Process conditions string for SPL query, or empty string if none.

        """
        url_path_conditions = []

        for parent_process_name in search_criteria.parent_process_names:
            uuids = self.parent_process_parser.extract_uuids_from_parent_process_name(
                parent_process_name
            )
            if uuids:
                inject_uuid, agent_uuid = uuids
                url_path_query = self.parent_process_parser.build_url_path_search_query(
                    inject_uuid, agent_uuid
                )
                if url_path_query:
                    url_path_conditions.append(url_path_query)
                    self.logger.debug(
                        f"{LOG_PREFIX} Added URL path condition for parent process: {url_path_query}"
                    )

        if url_path_conditions:
            return f"({' OR '.join(url_path_conditions)})"
        return ""

    @staticmethod
    def _build_sourcetype_filter(sourcetypes: list[str]) -> str:
        """Build the sourcetype filter from the configured sourcetype list."""
        names = [s.replace('"', "") for s in sourcetypes if s] or ["*"]
        if names == ["*"]:
            return "sourcetype=*"
        return "sourcetype IN (" + ",".join(f'"{n}"' for n in names) + ")"

    @staticmethod
    def _build_step_marker_clause(parent_process_names: list[str]) -> str:
        """Build the ``OR ("<marker>" ...)`` branch for the step marker.

        Markers are inject IDs (hex and dashes only), so quoting is safe.

        Returns:
            ``' OR ("m1" OR "m2")'`` or an empty string when the step has no marker.

        """
        markers = markers_from_parent_process(parent_process_names)
        if not markers:
            return ""
        return " OR (" + " OR ".join(f'"{m}"' for m in markers) + ")"

    @staticmethod
    def _build_ip_list(ips: list[str]) -> str:
        """Build a quoted comma-separated IP list for Splunk IN operator.

        Args:
            ips: List of IP addresses.

        Returns:
            Quoted CSV string for Splunk IN(), or "*" if empty.

        """
        if not ips:
            return "*"
        return ",".join(f'"{ip}"' for ip in ips)

    @staticmethod
    def _build_implant_url_list(parent_process_names: list[str]) -> str:
        """Build a quoted comma-separated implant callback URL list for Splunk IN operator.

        Args:
            parent_process_names: List of implant process names.

        Returns:
            Quoted CSV string for Splunk IN(), or ``"*"`` (wildcard) if empty.

        """
        if not parent_process_names:
            return "*"
        return ",".join(
            f'"/{name.replace(chr(34), chr(92) + chr(34))}/callback"'
            for name in parent_process_names
        )

    @staticmethod
    def _build_implant_name_list(parent_process_names: list[str]) -> str:
        """Build a quoted comma-separated implant process name list for Splunk IN operator.

        Args:
            parent_process_names: List of implant process names.

        Returns:
            Quoted CSV string for Splunk IN(), or ``"*"`` (wildcard) if empty.

        """
        if not parent_process_names:
            return "*"
        return ",".join(
            f'"{name.replace(chr(34), chr(92) + chr(34))}"'
            for name in parent_process_names
        )
