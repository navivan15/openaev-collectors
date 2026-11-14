"""Pydantic models for collector data structures."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Outcome(str, Enum):
    """The four outcomes a collector can reach for one expectation.

    * DETECTED / PREVENTED - the security tool saw / blocked the step.
    * MISSED - the tool was checked properly and has no matching alert.
    * COULD_NOT_CHECK - the collector never got a trustworthy answer
      (connection or auth failure, missing index, search error, or an
      expectation type this source cannot judge). Never scored as a miss.
    """

    DETECTED = "Detected"
    PREVENTED = "Prevented"
    MISSED = "Missed"
    COULD_NOT_CHECK = "Could not check"


class CouldNotCheckReason(str, Enum):
    """Why an expectation came out as Could not check.

    Names are source-neutral on purpose: the same model is meant to be used
    by other collectors (e.g. an EDR source), where "data source" is a tenant
    or an API scope rather than an index.
    """

    AUTH_FAILED = "auth_failed"
    SOURCE_UNREACHABLE = "source_unreachable"
    DATA_SOURCE_MISSING = "data_source_missing"
    SEARCH_FAILED = "search_failed"
    QUERY_REFUSED = "query_refused"
    EXPECTATION_NOT_SUPPORTED = "expectation_not_supported"
    COLLECTOR_ERROR = "collector_error"


class ExpectationTrace(BaseModel):
    """Pydantic model for expectation trace data.

    This model represents the structure of trace data that gets sent to the
    OpenAEV API for expectation tracking and validation.
    """

    inject_expectation_trace_expectation: str = Field(
        description="The expectation ID this trace is associated with"
    )
    inject_expectation_trace_source_id: str = Field(
        description="The collector/source ID that generated this trace"
    )
    inject_expectation_trace_alert_name: str = Field(
        description="Name of the alert that was matched"
    )
    inject_expectation_trace_alert_link: str = Field(
        description="Link to the alert in the source system"
    )
    inject_expectation_trace_date: str = Field(
        description="Date when the trace was created (ISO format string)"
    )

    @field_validator("inject_expectation_trace_expectation")
    @classmethod
    def expectation_must_not_be_empty(cls, v: str) -> str:
        """Validate that expectation ID is not empty.

        Args:
            v: The expectation ID value to validate.

        Returns:
            The trimmed expectation ID.

        Raises:
            ValueError: If the expectation ID is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Expectation ID cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_source_id")
    @classmethod
    def source_id_must_not_be_empty(cls, v: str) -> str:
        """Validate that source ID is not empty.

        Args:
            v: The source ID value to validate.

        Returns:
            The trimmed source ID.

        Raises:
            ValueError: If the source ID is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Source ID cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_alert_name")
    @classmethod
    def alert_name_must_not_be_empty(cls, v: str) -> str:
        """Validate that alert name is not empty.

        Args:
            v: The alert name value to validate.

        Returns:
            The trimmed alert name.

        Raises:
            ValueError: If the alert name is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Alert name cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_alert_link")
    @classmethod
    def alert_link_must_not_be_empty(cls, v: str) -> str:
        """Validate that alert link is not empty.

        Args:
            v: The alert link value to validate.

        Returns:
            The trimmed alert link.

        Raises:
            ValueError: If the alert link is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Alert link cannot be empty")
        return v.strip()

    @field_validator("inject_expectation_trace_date")
    @classmethod
    def date_must_not_be_empty(cls, v: str) -> str:
        """Validate that date is not empty.

        Args:
            v: The date value to validate.

        Returns:
            The trimmed date string.

        Raises:
            ValueError: If the date is empty or whitespace only.

        """
        if not v or not v.strip():
            raise ValueError("Trace date cannot be empty")
        return v.strip()

    def to_api_dict(self) -> dict[str, str]:
        """Convert the model to a dictionary suitable for API submission.

        This method ensures all values are strings as expected by the API,
        replacing the manual sanitization logic in the expectation manager.

        Returns:
            Dict with all values converted to strings.

        """
        return {
            key: str(value) if value is not None else ""
            for key, value in self.model_dump().items()
        }


class ExpectationResult(BaseModel):
    """Model for expectation processing results."""

    expectation_id: str = Field(..., description="ID of the processed expectation")
    is_valid: bool = Field(..., description="Whether the expectation was validated")
    expectation: Any | None = Field(None, description="The original expectation object")
    matched_alerts: list[dict[str, Any]] | None = Field(
        None, description="List of alerts that matched this expectation"
    )
    error_message: str | None = Field(
        None, description="Error message if processing failed"
    )
    skip_verdict: bool = Field(
        False,
        description=(
            "When True, the collector must NOT write a detection verdict for this "
            "expectation (e.g. Splunk auth/network failure, or an unsupported "
            "expectation type). The expectation is left pending so a transient "
            "failure is retried instead of being mislabelled 'Not Detected'."
        ),
    )
    processing_time: float | None = Field(
        None, description="Time taken to process this expectation in seconds"
    )
    outcome: Outcome | None = Field(
        None,
        description=(
            "One of Detected / Prevented / Missed / Could not check. Filled in "
            "from is_valid / skip_verdict when not set explicitly."
        ),
    )
    outcome_reason: str | None = Field(
        None,
        description="Machine-readable reason (a CouldNotCheckReason value, or "
        "a short miss reason such as 'no_alerts').",
    )
    match_method: str | None = Field(
        None,
        description="How the alert was tied to the step: 'step_marker' or "
        "'legacy' (IPs + implant parent process).",
    )
    match_field: str | None = Field(
        None,
        description="The alert field that carried the step marker, if any.",
    )
    search_path: str | None = Field(
        None,
        description="Which search found (or failed to find) the alert: "
        "'narrow' (remembered location) or 'wide'.",
    )

    @model_validator(mode="after")
    def _fill_outcome(self) -> "ExpectationResult":
        """Keep outcome, is_valid and skip_verdict consistent."""
        if self.outcome is None:
            if self.skip_verdict:
                self.outcome = Outcome.COULD_NOT_CHECK
            elif self.is_valid:
                kind = type(self.expectation).__name__ if self.expectation else ""
                self.outcome = (
                    Outcome.PREVENTED
                    if kind == "PreventionExpectation"
                    else Outcome.DETECTED
                )
            else:
                self.outcome = Outcome.MISSED
        if self.outcome == Outcome.COULD_NOT_CHECK:
            # Could not check must never be written back as a verdict.
            self.skip_verdict = True
            self.is_valid = False
        return self


class ProcessingSummary(BaseModel):
    """Model for expectation processing summary."""

    processed: int = Field(..., description="Total number of expectations processed")
    valid: int = Field(..., description="Number of valid expectations")
    invalid: int = Field(..., description="Number of invalid expectations")
    skipped: int = Field(..., description="Number of skipped expectations")
    outcomes: dict[str, int] = Field(
        default_factory=dict,
        description="Count per outcome (Detected / Prevented / Missed / Could not check)",
    )
    total_processing_time: float | None = Field(
        None, description="Total processing time in seconds"
    )
