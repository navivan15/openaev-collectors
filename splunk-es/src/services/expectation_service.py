"""Splunk ES Expectation Service Provider.

This module contains all the Splunk ES-specific logic for handling expectations.
It implements the service provider protocol and defines which signatures to support,
how to fetch data, and how to process expectations.
"""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from pyoaev.apis.inject_expectation.model import (  # type: ignore[import-untyped]
    DetectionExpectation,
    PreventionExpectation,
)
from pyoaev.helpers import OpenAEVDetectionHelper  # type: ignore[import-untyped]
from pyoaev.signatures.types import SignatureTypes  # type: ignore[import-untyped]

from ..collector.models import CouldNotCheckReason, ExpectationResult, Outcome
from ..models.configs.config_loader import ConfigLoader
from .client_api import SplunkESClientAPI
from .converter import Converter
from .exception import (
    SplunkESAPIError,
    SplunkESAuthenticationError,
    SplunkESConfigurationError,
    SplunkESDataConversionError,
    SplunkESExpectationError,
    SplunkESIndexNotFoundError,
    SplunkESMatchingError,
    SplunkESNetworkError,
    SplunkESNoAlertsFoundError,
    SplunkESNoMatchingAlertsError,
    SplunkESQueryError,
    SplunkESServiceError,
    SplunkESValidationError,
)
from .location_memory import LocationMemory
from .query_writer import (
    QueryWriter,
    TemplateStore,
    is_safe_field,
    is_safe_index,
    is_safe_sourcetype,
)
from .spl_validator import SplunkESQueryRefusedError
from .step_matching import KEY_SOURCE, KEY_TIME, StepContext, parse_time

LOG_PREFIX = "[SplunkESExpectationService]"


class SplunkESExpectationService:
    """Splunk ES-specific service provider for expectation handling.

    This class contains all the business logic specific to Splunk ES:
    - Which signature types to support (only IPV4/6 addresses)
    - How to fetch data from Splunk ES
    - How to validate expectations against data
    - How to handle batching and optimization
    """

    SUPPORTED_SIGNATURES = [
        SignatureTypes.SIG_TYPE_SOURCE_IPV4_ADDRESS,
        SignatureTypes.SIG_TYPE_TARGET_IPV4_ADDRESS,
        SignatureTypes.SIG_TYPE_SOURCE_IPV6_ADDRESS,
        SignatureTypes.SIG_TYPE_TARGET_IPV6_ADDRESS,
        SignatureTypes.SIG_TYPE_START_DATE,
        SignatureTypes.SIG_TYPE_END_DATE,
        SignatureTypes.SIG_TYPE_PARENT_PROCESS_NAME,
    ]

    def __init__(self, config: ConfigLoader | None = None) -> None:
        """Initialize the Splunk ES service provider.

        Args:
            config: Configuration loader instance for service settings.

        Raises:
            SplunkESValidationError: If config is None.
            SplunkESConfigurationError: If service components initialization fails.

        """
        if config is None:
            raise SplunkESValidationError("Config is required for expectation service")

        self.logger = logging.getLogger(__name__)
        self.config = config

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Initializing Splunk ES service components..."
            )
            self.client_api = SplunkESClientAPI(config)
            self.converter = Converter()
            self.logger.info(
                f"{LOG_PREFIX} Splunk ES expectation service initialized successfully"
            )
        except (SplunkESValidationError, SplunkESConfigurationError):
            raise
        except Exception as e:
            raise SplunkESConfigurationError(
                f"Failed to initialize Splunk ES service components: {e}"
            ) from e

        if (
            hasattr(config, "splunk_es")
            and hasattr(config.splunk_es, "time_window")
            and config.splunk_es.time_window
        ):
            self.time_window = config.splunk_es.time_window
            self.logger.debug(
                f"{LOG_PREFIX} Using configured time window: {self.time_window}"
            )
        else:
            self.time_window = timedelta(hours=1)
            self.logger.warning(
                f"{LOG_PREFIX} No time_window configured, using default 1 hour"
            )

        self.expectation_metadata: dict[str, dict[str, Any]] = {}
        self.last_cycle: dict[str, Any] = {}
        self._memory: LocationMemory | None = None
        self._writer: QueryWriter | None = None

        splunk_cfg = getattr(config, "splunk_es", None)
        before = getattr(splunk_cfg, "match_window_before", None)
        after = getattr(splunk_cfg, "match_window_after", None)
        self.match_window_before = (
            before if isinstance(before, timedelta) else timedelta(minutes=1)
        )
        self.match_window_after = (
            after if isinstance(after, timedelta) else timedelta(minutes=5)
        )

        if hasattr(config, "splunk_es"):
            self.max_retry = getattr(config.splunk_es, "max_retry", 3)
            self.offset = getattr(
                config.splunk_es, "offset", timedelta(seconds=30)
            ).total_seconds()
            self.logger.debug(
                f"{LOG_PREFIX} Using configured retry parameters: max_retry={self.max_retry}, offset={self.offset}s"
            )
        else:
            self.max_retry = 3
            self.offset = 30
            self.logger.warning(
                f"{LOG_PREFIX} No retry configuration found, using defaults: max_retry={self.max_retry}, offset={self.offset}s"
            )

    def get_supported_signatures(self) -> list[SignatureTypes]:
        """Get the signature types this service supports.

        Returns:
            List of SignatureTypes that this service can process.

        """
        self.logger.debug(
            f"{LOG_PREFIX} Returning {len(self.SUPPORTED_SIGNATURES)} supported signature types"
        )
        return self.SUPPORTED_SIGNATURES

    # ------------------------------------------------------------------
    # Batched flow: one narrow search over remembered locations, then one
    # wide search for everything else. See README "Query writer" and
    # "Location memory".
    # ------------------------------------------------------------------

    def set_expectation_metadata(self, metadata: dict[str, dict[str, Any]]) -> None:
        """Receive the raw OpenAEV fields per expectation id (asset, name, ...)."""
        self.expectation_metadata = metadata or {}

    def handle_batch_expectations(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation],
        detection_helper: OpenAEVDetectionHelper,
    ) -> list[ExpectationResult]:
        """Handle a batch of expectations.

        Default: all detection expectations of the cycle share one narrow
        search (remembered locations) and one wide search. When a custom
        ``SPLUNKES_QUERY_TEMPLATE`` is configured, each expectation is searched
        on its own with that template (still checked by the validator).
        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []
        if getattr(getattr(self.config, "splunk_es", None), "query_template", None):
            return self._handle_batch_per_step(expectations, detection_helper)
        try:
            return self._handle_batch_planned(expectations, detection_helper)
        except SplunkESServiceError:
            raise
        except Exception as e:
            raise SplunkESExpectationError(
                f"Error in handle_batch_expectations: {e}"
            ) from e

    def candidate_alerts(
        self, hosts: list[str], earliest: datetime, latest: datetime
    ) -> list[dict[str, Any]]:
        """Alerts naming these hosts in a time range (one checked search).

        For callers that judge alerts without a step marker, such as a
        learned-rule matcher comparing a step's window with a quiet window.
        Raises the same errors as a normal search, so a broken connection can
        be reported as Could not check.
        """
        self.client_api.ensure_index_available()
        spl = self._get_writer().host_window(hosts, earliest, latest)
        return self.converter.convert_data_to_oaev_data(self.client_api.run_search(spl))

    def _get_memory(self) -> LocationMemory:
        if self._memory is None:
            cfg = getattr(self.config, "splunk_es", None)
            self._memory = LocationMemory(
                getattr(cfg, "memory_path", None),
                ttl=getattr(cfg, "memory_ttl", timedelta(days=30)),
                wide_every=getattr(cfg, "memory_wide_every", 5),
            )
        return self._memory

    def _get_writer(self) -> QueryWriter:
        if self._writer is None:
            cfg = getattr(self.config, "splunk_es", None)
            self._writer = QueryWriter(
                TemplateStore(),
                index=self.client_api.alerts_index,
                sourcetypes=self.client_api.sourcetypes,
                limit=getattr(cfg, "search_limit", 1000),
            )
        return self._writer

    def _memory_key(
        self, expectation: DetectionExpectation, ctx: StepContext
    ) -> str | None:
        """Stable key for "the same test" across runs.

        OpenAEV gives each run new inject IDs, and the expectation payload has
        no test / payload identifier, so the key is the target asset plus the
        expectation name. Several tests on one asset share one entry.
        """
        meta = self.expectation_metadata.get(str(expectation.inject_expectation_id), {})
        asset = (
            meta.get("inject_expectation_asset")
            or (ctx.hostnames[0].strip().lower() if ctx.hostnames else None)
            or (ctx.target_ips[0] if ctx.target_ips else None)
            or (ctx.source_ips[0] if ctx.source_ips else None)
        )
        if not asset:
            return None
        name = str(meta.get("inject_expectation_name") or "").strip().lower()
        return f"asset:{asset}|expectation:{name}"

    def _is_due(
        self, ctx: StepContext, usual_delay: float | None, now: datetime
    ) -> bool:
        """A step is searched only after its alerts had time to arrive."""
        cfg = getattr(self.config, "splunk_es", None)
        margin = getattr(cfg, "alert_delay", timedelta(seconds=30))
        if not isinstance(margin, timedelta):
            margin = timedelta(seconds=30)
        if usual_delay is not None and ctx.start is not None:
            return now >= ctx.start + timedelta(seconds=usual_delay) + margin
        reference = ctx.end or ctx.start
        return reference is None or now >= reference + margin

    def _safe_process(
        self,
        expectation: Any,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Process one expectation on its own, turning errors into results."""
        try:
            return self.process_expectation(expectation, detection_helper)
        except SplunkESServiceError as e:
            return self._create_error_result_object(e, expectation)
        except Exception as e:
            return self._create_error_result_object(
                SplunkESExpectationError(f"Unexpected error: {e}"), expectation
            )

    def _handle_batch_planned(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation],
        detection_helper: OpenAEVDetectionHelper,
    ) -> list[ExpectationResult]:
        results: dict[int, ExpectationResult] = {}
        steps: list[dict[str, Any]] = []
        deferred = 0
        now = datetime.now(timezone.utc)
        memory = self._get_memory()

        for pos, expectation in enumerate(expectations):
            if not isinstance(expectation, DetectionExpectation):
                # Prevention (-> Could not check) and unknown types.
                results[pos] = self._safe_process(expectation, detection_helper)
                continue
            try:
                _, matching_signatures = self._extract_signatures(expectation)
                ctx = self._build_step_context(expectation)
                if not ctx.markers and not ctx.ips:
                    raise SplunkESExpectationError(
                        "Expectation has no step marker and no IP signature to search for"
                    )
            except SplunkESServiceError as e:
                results[pos] = self._create_error_result_object(e, expectation)
                continue
            key = self._memory_key(expectation, ctx)
            if not self._is_due(ctx, memory.usual_delay(key), now):
                deferred += 1
                continue
            locations, lookup = memory.lookup(key)
            steps.append(
                {
                    "pos": pos,
                    "expectation": expectation,
                    "ctx": ctx,
                    "matching": matching_signatures,
                    "key": key,
                    "locations": locations,
                    "lookup": lookup,
                }
            )

        self.last_cycle = {
            "deferred": deferred,
            "narrow_searches": 0,
            "wide_searches": 0,
            "lookups": {s["pos"]: s["lookup"] for s in steps},
        }
        if deferred:
            self.logger.info(
                f"{LOG_PREFIX} {deferred} expectation(s) not searched yet: their "
                f"alerts have not had time to arrive"
            )
        if steps:
            self._search_and_match(steps, detection_helper, results)
        self.logger.info(
            f"{LOG_PREFIX} Cycle searches: narrow={self.last_cycle['narrow_searches']} "
            f"wide={self.last_cycle['wide_searches']} for {len(steps)} step(s)"
        )
        return [results[pos] for pos in sorted(results)]

    def _fail_steps(
        self,
        steps: list[dict[str, Any]],
        error: SplunkESServiceError,
        results: dict[int, ExpectationResult],
        search_path: str | None,
    ) -> None:
        for step in steps:
            if step["pos"] in results:
                continue
            result = self._create_error_result_object(error, step["expectation"])
            result.search_path = search_path
            results[step["pos"]] = result

    def _search_window(
        self, steps: list[dict[str, Any]], tight: bool
    ) -> tuple[datetime, datetime]:
        """Time range covering all steps (tight = remembered delay only)."""
        now = datetime.now(timezone.utc)
        starts, ends = [], []
        for step in steps:
            ctx: StepContext = step["ctx"]
            if ctx.window_start:
                starts.append(ctx.window_start)
            end = ctx.window_end
            if tight and ctx.start is not None:
                delays = [
                    float(loc["delay_seconds"])
                    for loc in step["locations"]
                    if loc.get("delay_seconds") is not None
                ]
                tight_end = ctx.start + timedelta(
                    seconds=2 * max(delays, default=0.0) + 60
                )
                if ctx.end is not None:
                    tight_end = max(tight_end, ctx.end + timedelta(seconds=60))
                end = min(end, tight_end) if end else tight_end
            if end:
                ends.append(end)
        earliest = min(starts) if starts else now - self.time_window
        latest = max(ends) if ends else now
        return earliest, latest

    def _try_match(
        self,
        oaev_data: list[dict[str, Any]],
        step: dict[str, Any],
        detection_helper: OpenAEVDetectionHelper,
    ) -> tuple[dict[str, Any] | None, str]:
        try:
            hit = self._match(
                oaev_data,
                step["matching"],
                detection_helper,
                "detection",
                step_context=step["ctx"],
            )
            return hit, ""
        except SplunkESNoAlertsFoundError:
            return None, "no_alerts"
        except SplunkESNoMatchingAlertsError as e:
            return None, e.reason

    def _detected(
        self, step: dict[str, Any], hit: dict[str, Any], search_path: str
    ) -> ExpectationResult:
        result = self._convert_dict_to_result(hit, step["expectation"])
        result.search_path = search_path
        self._remember(step, hit, search_path)
        return result

    def _remember(
        self, step: dict[str, Any], hit: dict[str, Any], search_path: str
    ) -> None:
        """Record where this step's detection was found."""
        item = (hit.get("matching_data") or [{}])[0]
        source = item.get(KEY_SOURCE) or {}
        index = source.get("index") or self.client_api.alerts_index
        sourcetype = source.get("sourcetype")
        if not (index and sourcetype):
            return
        if not is_safe_index(index) or not is_safe_sourcetype(sourcetype):
            return
        field = hit.get("match_field")
        ctx: StepContext = step["ctx"]
        alert_time = parse_time(item.get(KEY_TIME))
        delay = (
            max(0.0, (alert_time - ctx.start).total_seconds())
            if alert_time and ctx.start
            else None
        )
        self._get_memory().record(
            step["key"],
            index=index,
            sourcetype=sourcetype,
            field=field if field and is_safe_field(field) else None,
            rule_name=source.get("rule_name"),
            delay_seconds=delay,
            search_path=search_path,
        )

    def _search_and_match(
        self,
        steps: list[dict[str, Any]],
        detection_helper: OpenAEVDetectionHelper,
        results: dict[int, ExpectationResult],
    ) -> None:
        try:
            writer = self._get_writer()
            self.client_api.ensure_index_available()
        except SplunkESServiceError as e:
            self._fail_steps(steps, e, results, None)
            return

        narrow = [s for s in steps if s["locations"]]
        wide = [s for s in steps if not s["locations"]]

        # --- narrow: remembered locations only, one search -------------------
        if narrow:
            try:
                by_location: dict[tuple[str, str], list[StepContext]] = {}
                for step in narrow:
                    for loc in step["locations"]:
                        by_location.setdefault(
                            (loc["index"], loc["sourcetype"]), []
                        ).append(step["ctx"])
                earliest, latest = self._search_window(narrow, tight=True)
                spl = writer.narrow(by_location, earliest, latest)
                self.last_cycle["narrow_searches"] += 1
                data = self.converter.convert_data_to_oaev_data(
                    self.client_api.run_search(spl)
                )
                for step in narrow:
                    hit, _ = self._try_match(data, step, detection_helper)
                    if hit:
                        results[step["pos"]] = self._detected(step, hit, "narrow")
            except SplunkESServiceError as e:
                if self._could_not_check_reason(e) in (
                    CouldNotCheckReason.AUTH_FAILED,
                    CouldNotCheckReason.SOURCE_UNREACHABLE,
                    CouldNotCheckReason.QUERY_REFUSED,
                ):
                    # A broken connection is Could not check on this path too.
                    self._fail_steps(narrow, e, results, "narrow")
                else:
                    self.logger.warning(
                        f"{LOG_PREFIX} Narrow search failed ({e}); using the wide search"
                    )
            # Guard 1: not found in the remembered place -> wide search before
            # the outcome may be Missed.
            wide.extend(s for s in narrow if s["pos"] not in results)

        # --- wide: configured index + sourcetypes, one search (+ retries) ----
        if not wide:
            return
        pending = list(wide)
        reasons: dict[int, str] = {}
        try:
            earliest, latest = self._search_window(wide, tight=False)
            for attempt in range(int(self.max_retry) + 1):
                if attempt:
                    time.sleep(self.offset)
                spl = writer.wide([s["ctx"] for s in pending], earliest, latest)
                self.last_cycle["wide_searches"] += 1
                data = self.converter.convert_data_to_oaev_data(
                    self.client_api.run_search(spl)
                )
                still = []
                for step in pending:
                    hit, reason = self._try_match(data, step, detection_helper)
                    if hit:
                        results[step["pos"]] = self._detected(step, hit, "wide")
                    else:
                        reasons[step["pos"]] = reason
                        still.append(step)
                pending = still
                if not pending:
                    break
        except SplunkESServiceError as e:
            self._fail_steps(pending, e, results, "wide")
            return

        for step in pending:
            reason = reasons.get(step["pos"], "no_alerts")
            error: SplunkESServiceError = (
                SplunkESNoAlertsFoundError("No data available for matching")
                if reason == "no_alerts"
                else SplunkESNoMatchingAlertsError(reason=reason)
            )
            result = self._create_error_result_object(error, step["expectation"])
            result.search_path = "wide"
            results[step["pos"]] = result
            # Neither place has it: the remembered location is no longer true.
            self._get_memory().forget(step["key"])

    def _handle_batch_per_step(
        self,
        expectations: list[DetectionExpectation | PreventionExpectation],
        detection_helper: OpenAEVDetectionHelper,
    ) -> list[ExpectationResult]:
        """Handle a batch of expectations.

        Processes each expectation individually and collects results,
        handling errors gracefully for individual expectations.

        Args:
            expectations: List of expectations to process.
            detection_helper: OpenAEV detection helper.

        Returns:
            List of ExpectationResult objects.

        Raises:
            SplunkESExpectationError: If batch processing fails.

        """
        if not expectations:
            self.logger.info(f"{LOG_PREFIX} No expectations to process")
            return []

        try:
            self.logger.info(
                f"{LOG_PREFIX} Starting batch processing of {len(expectations)} expectations"
            )

            all_results_with_expectations_associated = []

            for i, expectation in enumerate(expectations, 1):
                expectation_id = str(expectation.inject_expectation_id)
                self.logger.debug(
                    f"{LOG_PREFIX} Processing expectation {i}/{len(expectations)}: {expectation_id}"
                )

                try:
                    result = self.process_expectation(expectation, detection_helper)
                    if result.is_valid:
                        self.logger.debug(
                            f"{LOG_PREFIX} Expectation {expectation_id} processed successfully"
                        )
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Expectation {expectation_id} failed validation"
                        )

                except SplunkESServiceError as e:
                    self.logger.warning(
                        f"{LOG_PREFIX} Splunk ES service error for expectation {expectation_id}: {e}"
                    )
                    result = self._create_error_result_object(e, expectation)
                except Exception as e:
                    self.logger.error(
                        f"{LOG_PREFIX} Unexpected error processing expectation {expectation_id}: {e}"
                    )
                    result = self._create_error_result_object(
                        SplunkESExpectationError(f"Unexpected error: {e}"),
                        expectation,
                    )

                all_results_with_expectations_associated.append(result)

            valid_count = sum(
                1 for r in all_results_with_expectations_associated if r.is_valid
            )
            invalid_count = len(all_results_with_expectations_associated) - valid_count

            self.logger.info(
                f"{LOG_PREFIX} Batch expectation processing: processed {len(expectations)} items -> {len(all_results_with_expectations_associated)} results"
            )
            self.logger.info(
                f"{LOG_PREFIX} Batch processing completed: {valid_count} valid, {invalid_count} invalid"
            )

            return all_results_with_expectations_associated

        except Exception as e:
            raise SplunkESExpectationError(
                f"Error in handle_batch_expectations: {e}"
            ) from e

    def process_expectation(
        self,
        expectation: DetectionExpectation | PreventionExpectation,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Process a single expectation based on its type.

        Args:
            expectation: The expectation to process (Detection only for Splunk ES).
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        Raises:
            SplunkESExpectationError: If expectation type is unsupported.

        """
        expectation_id = str(expectation.inject_expectation_id)

        if isinstance(expectation, DetectionExpectation):
            self.logger.debug(
                f"{LOG_PREFIX} Processing detection expectation: {expectation_id}"
            )
            return self.handle_detection_expectation(expectation, detection_helper)
        elif isinstance(expectation, PreventionExpectation):
            self.logger.warning(
                f"{LOG_PREFIX} Splunk ES service warning for expectation {expectation_id}: Splunk ES only supports DetectionExpectations, not PreventionExpectations, marking them as invalid"
            )
            return ExpectationResult(
                expectation_id=expectation_id,
                is_valid=False,
                expectation=expectation,
                error_message="Splunk ES only supports DetectionExpectations, not PreventionExpectations",
                skip_verdict=True,
                outcome=Outcome.COULD_NOT_CHECK,
                outcome_reason=CouldNotCheckReason.EXPECTATION_NOT_SUPPORTED.value,
            )
        else:
            self.logger.error(
                f"{LOG_PREFIX} Unsupported expectation type for {expectation_id}: {type(expectation).__name__}"
            )
            raise SplunkESExpectationError(
                f"Unsupported expectation type: {type(expectation).__name__}"
            )

    def handle_detection_expectation(
        self,
        expectation: DetectionExpectation,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Handle a detection expectation.

        Args:
            expectation: The detection expectation to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult containing the processing outcome.

        """
        result_dict = self._handle_expectation(
            expectation, detection_helper, "detection"
        )
        return self._convert_dict_to_result(result_dict, expectation)

    def handle_prevention_expectation(
        self,
        expectation: PreventionExpectation,
        detection_helper: OpenAEVDetectionHelper,
    ) -> ExpectationResult:
        """Handle a prevention expectation.

        Since Splunk ES only supports detection, this method logs a warning
        and returns an invalid result instead of throwing an error.

        Args:
            expectation: The prevention expectation to process.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            ExpectationResult indicating that prevention is not supported.

        """
        expectation_id = str(expectation.inject_expectation_id)
        self.logger.warning(
            f"{LOG_PREFIX} Splunk ES service error for expectation {expectation_id}: Splunk ES only supports DetectionExpectations, not PreventionExpectations"
        )
        return ExpectationResult(
            expectation_id=expectation_id,
            is_valid=False,
            expectation=expectation,
            error_message="Splunk ES only supports DetectionExpectations, not PreventionExpectations",
            skip_verdict=True,
            outcome=Outcome.COULD_NOT_CHECK,
            outcome_reason=CouldNotCheckReason.EXPECTATION_NOT_SUPPORTED.value,
        )

    def _handle_expectation(
        self,
        expectation: DetectionExpectation,
        detection_helper: OpenAEVDetectionHelper,
        expectation_type: str,
    ) -> dict[str, Any]:
        """Core logic for handling expectations.

        Args:
            expectation: The expectation to process.
            detection_helper: OpenAEV detection helper instance.
            expectation_type: Type of expectation ('detection').

        Returns:
            Dictionary containing processing results.

        Raises:
            SplunkESExpectationError: If expectation processing fails.

        """
        expectation_id = expectation.inject_expectation_id

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Starting {expectation_type} expectation processing: {expectation_id}"
            )

            self.logger.debug(f"{LOG_PREFIX} Extracting signatures from expectation...")
            search_signatures, matching_signatures = self._extract_signatures(
                expectation
            )
            self.logger.debug(
                f"{LOG_PREFIX} Extracted {len(search_signatures)} search signatures, {len(matching_signatures)} matching signatures"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Fetching Splunk ES data for {expectation_type} expectation..."
            )
            splunk_es_data = self.client_api.fetch_with_retry(
                search_signatures, expectation_type, self.max_retry, int(self.offset)
            )
            self.logger.debug(
                f"{LOG_PREFIX} Fetched {len(splunk_es_data)} data items from Splunk ES"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Converting Splunk ES data to OAEV format..."
            )
            oaev_data = self.converter.convert_data_to_oaev_data(splunk_es_data)
            self.logger.debug(
                f"{LOG_PREFIX} Converted to {len(oaev_data)} OAEV data items"
            )

            self.logger.debug(
                f"{LOG_PREFIX} Matching data against expectation signatures..."
            )
            step_context = self._build_step_context(expectation)
            result = self._match(
                oaev_data,
                matching_signatures,
                detection_helper,
                expectation_type,
                step_context=step_context,
            )

            return result

        except (
            SplunkESServiceError,
            SplunkESAPIError,
            SplunkESNetworkError,
            SplunkESDataConversionError,
        ):
            raise
        except Exception as e:
            raise SplunkESExpectationError(
                f"Unexpected error processing expectation: {e}"
            ) from e

    def _extract_signatures(
        self, expectation: DetectionExpectation
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        """Extract and filter signatures from expectation.

        Args:
            expectation: The expectation to extract signatures from.

        Returns:
            Tuple of (search_signatures, matching_signatures):
            - search_signatures: signatures for API query building
            - matching_signatures: signatures for alert matching (excludes date metadata)

        Raises:
            SplunkESExpectationError: If signature extraction fails.

        """
        try:
            all_signatures = [
                {"type": sig.type.value, "value": sig.value}
                for sig in expectation.inject_expectation_signatures
            ]
            self.logger.debug(
                f"{LOG_PREFIX} Found {len(all_signatures)} total signatures in expectation"
            )

            search_signatures = [
                sig
                for sig in all_signatures
                if sig["type"] in [s.value for s in self.SUPPORTED_SIGNATURES]
            ]

            date_signature_types = [
                SignatureTypes.SIG_TYPE_START_DATE.value,
                SignatureTypes.SIG_TYPE_END_DATE.value,
            ]
            matching_signatures = [
                sig
                for sig in search_signatures
                if sig["type"] not in date_signature_types
            ]

            self.logger.debug(
                f"{LOG_PREFIX} Filtered to {len(search_signatures)} search signatures and {len(matching_signatures)} matching signatures"
            )

            return search_signatures, matching_signatures

        except Exception as e:
            raise SplunkESExpectationError(
                f"Failed to extract signatures from expectation: {e}"
            ) from e

    def _build_step_context(self, expectation: DetectionExpectation) -> StepContext:
        """Collect marker, host and time window for the step behind an expectation."""
        signatures = []
        for sig in getattr(expectation, "inject_expectation_signatures", []) or []:
            sig_type = getattr(sig.type, "value", sig.type)
            signatures.append({"type": str(sig_type), "value": str(sig.value)})
        return StepContext.from_signatures(
            signatures, self.match_window_before, self.match_window_after
        )

    def _match(
        self,
        oaev_data: list[dict[str, Any]],
        matching_signatures: list[dict[str, str]],
        detection_helper: OpenAEVDetectionHelper,
        expectation_type: str,
        step_context: StepContext | None = None,
    ) -> dict[str, Any]:
        """Match OAEV data against expectation signatures.

        Per alert, in order:

        1. Time window - an alert stamped outside the step's window (with
           slack) cannot have been caused by it.
        2. Host - when both the step and the alert name a host, they must
           agree (falls back to IPs when no hostname is available).
        3. Step marker - an alert carrying the step's marker (inject ID) in a
           command line, file name or hostname field is tied to this step.
        4. Legacy fallback - IPs + implant parent process (from the implant
           callback URL). When the step has a marker, the implant identity is
           required: an IP-only coincidence no longer counts for it.

        Args:
            oaev_data: List of OAEV formatted data.
            matching_signatures: Signatures to match against.
            detection_helper: OpenAEV detection helper.
            expectation_type: Type of expectation ('detection').
            step_context: Marker / host / time window for the step. None keeps
                the legacy behaviour exactly.

        Returns:
            Result dictionary with match status and matching data.

        Raises:
            SplunkESNoAlertsFoundError: If no data available for matching.
            SplunkESNoMatchingAlertsError: If no matching alerts found.
            SplunkESMatchingError: If matching process fails.

        """
        try:
            if not oaev_data:
                self.logger.debug(f"{LOG_PREFIX} No OAEV data available for matching")
                raise SplunkESNoAlertsFoundError("No data available for matching")

            self.logger.debug(
                f"{LOG_PREFIX} Attempting to match {len(oaev_data)} data items against {len(matching_signatures)} signatures"
            )

            ctx = step_context or StepContext()
            rejections: list[str] = []

            for i, data_item in enumerate(oaev_data):
                self.logger.debug(f"{i} data_item: {data_item}")
                self.logger.debug(
                    f"{LOG_PREFIX} Matching data item {i + 1}/{len(oaev_data)}"
                )

                if ctx.in_time_window(data_item) is False:
                    self.logger.debug(
                        f"{LOG_PREFIX} Data item {i + 1} is outside the step time window"
                    )
                    rejections.append("outside_time_window")
                    continue

                if ctx.hostname_check(data_item) is False:
                    self.logger.debug(
                        f"{LOG_PREFIX} Data item {i + 1} names a different host"
                    )
                    rejections.append("wrong_host")
                    continue

                marker_field = ctx.marker_found(data_item)
                if marker_field:
                    if ctx.host_check(data_item) is False:
                        self.logger.debug(
                            f"{LOG_PREFIX} Data item {i + 1} carries the step marker "
                            f"but its IPs belong to another host"
                        )
                        rejections.append("wrong_host")
                        continue
                    self.logger.info(
                        f"{LOG_PREFIX} Step marker match for {expectation_type} "
                        f"expectation (field '{marker_field}')"
                    )
                    return {
                        "is_valid": True,
                        "matching_data": [data_item],
                        "total_data_found": len(oaev_data),
                        "match_method": "step_marker",
                        "match_field": marker_field,
                    }

                if ctx.markers and "parent_process_name" not in data_item:
                    # The step has a marker but this alert carries neither the
                    # marker nor the implant identity: it cannot be tied to
                    # this step (e.g. a stale alert sharing only the IPs).
                    self.logger.debug(
                        f"{LOG_PREFIX} Data item {i + 1} has no step marker or "
                        f"implant identity - not tied to this step"
                    )
                    rejections.append("marker_absent")
                    continue

                available_signatures = [
                    sig for sig in matching_signatures if sig["type"] in data_item
                ]

                self.logger.debug(
                    f"{LOG_PREFIX} Data item {i + 1} has {len(available_signatures)} available signatures out of {len(matching_signatures)} total signatures"
                )

                if available_signatures:
                    try:
                        self.logger.debug(
                            f"{LOG_PREFIX} Testing match for data item {i + 1} with {len(available_signatures)} signatures"
                        )

                        # Use detection_helper with filtered signatures per type
                        if self._match_with_detection_helper(
                            available_signatures, data_item, detection_helper
                        ):
                            self.logger.debug(
                                f"{LOG_PREFIX} Match found for data item {i + 1}!"
                            )

                            self.logger.info(
                                f"{LOG_PREFIX} Successful match found for {expectation_type} expectation"
                            )
                            self.logger.debug(
                                f"{LOG_PREFIX} Matching data: {data_item}"
                            )

                            result = {
                                "is_valid": True,
                                "matching_data": [data_item],
                                "total_data_found": len(oaev_data),
                                "match_method": "legacy",
                            }

                            return result
                        else:
                            self.logger.debug(
                                f"{LOG_PREFIX} No match for data item {i + 1}"
                            )
                            rejections.append("no_matching_alert")
                            continue
                    except Exception as e:
                        self.logger.error(
                            f"{LOG_PREFIX} Error during matching for data item {i + 1}: {e}"
                        )
                        raise SplunkESNoMatchingAlertsError() from e
                else:
                    self.logger.debug(
                        f"{LOG_PREFIX} Data item {i + 1} has no available signatures to match against"
                    )

            reason = "no_matching_alert"
            for candidate in ("wrong_host", "outside_time_window", "marker_absent"):
                if candidate in rejections:
                    reason = candidate
                    break
            self.logger.info(
                f"{LOG_PREFIX} No matching alerts found after checking "
                f"{len(oaev_data)} data items (reason={reason})"
            )
            raise SplunkESNoMatchingAlertsError(reason=reason)

        except (
            SplunkESServiceError,
            SplunkESNoAlertsFoundError,
            SplunkESNoMatchingAlertsError,
        ):
            raise
        except Exception as e:
            raise SplunkESMatchingError() from e

    def _match_with_detection_helper(
        self,
        signatures: list[dict[str, str]],
        data_item: dict[str, Any],
        detection_helper: OpenAEVDetectionHelper,
    ) -> bool:
        """Match signatures using detection_helper with proper OR logic.

        Args:
            signatures: List of signature dictionaries.
            data_item: OAEV data item to match against.
            detection_helper: OpenAEV detection helper instance.

        Returns:
            True if matching succeeds, False otherwise.

        Logic:
        1. Parent process: MUST match exactly (if present) - stop if False
        2. Source IPs: Call detection_helper for each IP individually, stop at first match (OR logic)
        3. Target IPs: Call detection_helper for each IP individually, stop at first match (OR logic)
        4. Must have parent_process=True AND (at least one src_ip=True OR at least one dst_ip=True)

        """
        try:
            signature_groups: dict[str, list[dict[str, str]]] = {}
            for sig in signatures:
                sig_type = sig["type"]
                if sig_type not in signature_groups:
                    signature_groups[sig_type] = []
                signature_groups[sig_type].append(sig)

            self.logger.debug(
                f"{LOG_PREFIX} Processing {len(signature_groups)} signature groups"
            )

            parent_process_match = False
            source_ip_match = False
            target_ip_match = False

            if "parent_process_name" in signature_groups:
                parent_sigs = signature_groups["parent_process_name"]
                self.logger.debug(
                    f"{LOG_PREFIX} Checking parent process with {len(parent_sigs)} signatures"
                )

                filtered_data = {
                    k: v for k, v in data_item.items() if k == "parent_process_name"
                }

                parent_process_match = detection_helper.match_alert_elements(
                    parent_sigs, filtered_data
                )

                self.logger.debug(
                    f"{LOG_PREFIX} Parent process match: {parent_process_match}"
                )

                if not parent_process_match:
                    self.logger.debug(f"{LOG_PREFIX} Parent process failed - stopping")
                    return False

            source_ip_types = ["source_ipv4_address", "source_ipv6_address"]
            for ip_type in source_ip_types:
                if ip_type in signature_groups and ip_type in data_item:
                    ip_sigs = signature_groups[ip_type]
                    self.logger.debug(
                        f"{LOG_PREFIX} Checking {ip_type} with {len(ip_sigs)} signatures"
                    )

                    for sig in ip_sigs:
                        filtered_data = {ip_type: data_item[ip_type]}
                        if detection_helper.match_alert_elements([sig], filtered_data):
                            self.logger.debug(
                                f"{LOG_PREFIX} ✓ {ip_type} signature matched: {sig['value']}"
                            )
                            source_ip_match = True
                            break

                    if source_ip_match:
                        break

            target_ip_types = ["target_ipv4_address", "target_ipv6_address"]
            for ip_type in target_ip_types:
                if ip_type in signature_groups and ip_type in data_item:
                    ip_sigs = signature_groups[ip_type]
                    self.logger.debug(
                        f"{LOG_PREFIX} Checking {ip_type} with {len(ip_sigs)} signatures"
                    )

                    for sig in ip_sigs:
                        filtered_data = {ip_type: data_item[ip_type]}
                        if detection_helper.match_alert_elements([sig], filtered_data):
                            self.logger.debug(
                                f"{LOG_PREFIX} ✓ {ip_type} signature matched: {sig['value']}"
                            )
                            target_ip_match = True
                            break

                    if target_ip_match:
                        break

            has_parent_sigs = "parent_process_name" in signature_groups
            has_source_sigs = any(t in signature_groups for t in source_ip_types)
            has_target_sigs = any(t in signature_groups for t in target_ip_types)

            self.logger.debug(
                f"{LOG_PREFIX} Match results - Parent: {parent_process_match} "
                f"(required: {has_parent_sigs}), "
                f"Source IP: {source_ip_match} (required: {has_source_sigs}), "
                f"Target IP: {target_ip_match} (required: {has_target_sigs})"
            )

            # A parent-process match is only REQUIRED when the expectation actually
            # carries a parent-process signature. Network / agentless injects expose
            # only IP signatures; demanding a parent-process match for those makes
            # them permanently undetectable (false "Not Detected"), so gate on
            # has_parent_sigs instead of on parent_process_match unconditionally.
            if has_parent_sigs and not parent_process_match:
                return False

            if has_source_sigs and has_target_sigs:
                ip_result = source_ip_match or target_ip_match
            elif has_source_sigs:
                ip_result = source_ip_match
            elif has_target_sigs:
                ip_result = target_ip_match
            else:
                ip_result = True

            # Require at least one positive signal so an expectation with no usable
            # signatures is never counted as a match.
            if not (has_parent_sigs or has_source_sigs or has_target_sigs):
                self.logger.debug(
                    f"{LOG_PREFIX} No matchable signatures present - no match"
                )
                return False

            result = ip_result
            self.logger.debug(f"{LOG_PREFIX} Final match result: {result}")
            return result

        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error in detection_helper matching: {e}")
            return False

    def _create_error_result(
        self,
        error: SplunkESServiceError,
        expectation: DetectionExpectation | None = None,
    ) -> dict[str, Any]:
        """Create an error result dictionary from a Splunk ES service error.

        Args:
            error: The Splunk ES service error that occurred.
            expectation: Optional expectation object that caused the error.

        Returns:
            Dictionary containing error details and metadata.

        """
        result = {
            "is_valid": False,
            "error": str(error),
            "error_type": error.__class__.__name__,
        }

        if hasattr(error, "status_code") and error.status_code:
            result["status_code"] = error.status_code

        if hasattr(error, "response_data") and error.response_data:
            result["response_data"] = error.response_data

        if expectation:
            result["expectation"] = expectation
            result["expectation_id"] = str(expectation.inject_expectation_id)

        return result

    def _create_error_result_object(
        self,
        error: SplunkESServiceError,
        expectation: DetectionExpectation | None = None,
    ) -> ExpectationResult:
        """Create an ExpectationResult object from a Splunk ES service error.

        Args:
            error: The Splunk ES service error that occurred.
            expectation: Optional expectation object that caused the error.

        Returns:
            ExpectationResult object with error details.

        """
        expectation_id = (
            str(expectation.inject_expectation_id) if expectation else "unknown"
        )

        error_message = str(error)
        if hasattr(error, "status_code") and error.status_code:
            error_message += f" (Status: {error.status_code})"

        # Distinguish a genuine "the tool did not detect it" outcome from an
        # infrastructure failure. Only "no alerts / no matching alerts" is a real
        # negative detection that should be written back as "Not Detected".
        # Auth/network/API/config failures mean we never got a trustworthy answer
        # from Splunk, so we must NOT score them as a miss (that would make a
        # broken integration look like a failed security control).
        genuine_negative = isinstance(
            error, (SplunkESNoAlertsFoundError, SplunkESNoMatchingAlertsError)
        )
        if genuine_negative:
            reason = (
                getattr(error, "reason", None)
                if isinstance(error, SplunkESNoMatchingAlertsError)
                else "no_alerts"
            )
            return ExpectationResult(
                expectation_id=expectation_id,
                is_valid=False,
                expectation=expectation,
                error_message=error_message,
                skip_verdict=False,
                outcome=Outcome.MISSED,
                outcome_reason=reason,
            )

        reason = self._could_not_check_reason(error)
        self.logger.error(
            f"{LOG_PREFIX} Could not check expectation {expectation_id} "
            f"({error.__class__.__name__}, reason={reason.value}) - leaving it "
            f"pending instead of scoring it 'Not Detected': {error_message}"
        )
        return ExpectationResult(
            expectation_id=expectation_id,
            is_valid=False,
            expectation=expectation,
            error_message=error_message,
            skip_verdict=True,
            outcome=Outcome.COULD_NOT_CHECK,
            outcome_reason=reason.value,
        )

    @staticmethod
    def _could_not_check_reason(error: BaseException) -> CouldNotCheckReason:
        """Classify an infrastructure error, following the exception chain."""
        chain: list[BaseException] = []
        current: BaseException | None = error
        while current is not None and current not in chain:
            chain.append(current)
            current = current.__cause__ or current.__context__
        if any(isinstance(e, SplunkESQueryRefusedError) for e in chain):
            return CouldNotCheckReason.QUERY_REFUSED
        if any(isinstance(e, SplunkESAuthenticationError) for e in chain):
            return CouldNotCheckReason.AUTH_FAILED
        if any(isinstance(e, SplunkESIndexNotFoundError) for e in chain):
            return CouldNotCheckReason.DATA_SOURCE_MISSING
        if any(isinstance(e, SplunkESNetworkError) for e in chain):
            return CouldNotCheckReason.SOURCE_UNREACHABLE
        if any(isinstance(e, (SplunkESAPIError, SplunkESQueryError)) for e in chain):
            return CouldNotCheckReason.SEARCH_FAILED
        return CouldNotCheckReason.COLLECTOR_ERROR

    def _convert_dict_to_result(
        self,
        result_dict: dict[str, Any],
        expectation: DetectionExpectation,
    ) -> ExpectationResult:
        """Convert a dictionary result to ExpectationResult object.

        Args:
            result_dict: Dictionary containing processing results.
            expectation: The expectation that was processed.

        Returns:
            ExpectationResult object with structured data.

        """
        return ExpectationResult(
            expectation_id=str(expectation.inject_expectation_id),
            is_valid=result_dict.get("is_valid", False),
            expectation=expectation,
            matched_alerts=result_dict.get("matching_data"),
            error_message=result_dict.get("error"),
            match_method=result_dict.get("match_method"),
            match_field=result_dict.get("match_field"),
        )

    def get_service_info(self) -> dict[str, Any]:
        """Get information about this service provider.

        Returns:
            Dictionary containing service metadata and capabilities.

        """
        info = {
            "service_name": "Splunk ES",
            "supported_signatures": [sig.value for sig in self.SUPPORTED_SIGNATURES],
            "supports_detection": True,
            "supports_prevention": False,
            "description": f"Splunk ES expectation validation service ({len(self.SUPPORTED_SIGNATURES)} signature types, detection only)",
        }
        self.logger.debug(f"{LOG_PREFIX} Service info: {info}")
        return info
