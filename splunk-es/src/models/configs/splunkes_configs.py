"""Configuration for SplunkES integration."""

from datetime import timedelta
from typing import Optional

from pydantic import Field, SecretStr
from src.models.configs import ConfigBaseSettings


class _ConfigLoaderSplunkES(ConfigBaseSettings):
    """SplunkES API configuration settings.

    Contains connection details, timing parameters, and retry settings
    for SplunkES API integration.
    """

    model_config = {"frozen": False}

    base_url: str = Field(
        alias="SPLUNKES_BASE_URL",
        description="Base URL for the Splunk ES instance (e.g., https://splunk.company.com:8089).",
    )
    username: Optional[str] = Field(
        alias="SPLUNKES_USERNAME",
        default=None,
        description="Username for Splunk ES basic authentication. "
        "Ignored when SPLUNKES_TOKEN is set.",
    )
    password: Optional[SecretStr] = Field(
        alias="SPLUNKES_PASSWORD",
        default=None,
        description="Password for Splunk ES basic authentication. "
        "Ignored when SPLUNKES_TOKEN is set.",
    )
    token: Optional[SecretStr] = Field(
        alias="SPLUNKES_TOKEN",
        default=None,
        description="Splunk authentication token (bearer). When set, it is used "
        "instead of username/password via an 'Authorization: Bearer <token>' "
        "header. Preferred over basic auth for Splunk Cloud / hardened setups.",
    )
    verify_ssl: bool = Field(
        alias="SPLUNKES_VERIFY_SSL",
        default=True,
        description="Whether to verify the Splunk TLS certificate. Defaults to True. "
        "Set to False only for self-signed lab instances.",
    )
    alerts_index: Optional[str] = Field(
        alias="SPLUNKES_ALERTS_INDEX",
        default="main",
        description="Index to search for alerts (default: _notable).",
    )
    time_window: Optional[timedelta] = Field(
        alias="SPLUNKES_TIME_WINDOW",
        default=timedelta(hours=1),
        description="Time window for searches when no dates provided.",
    )
    max_retry: int = Field(
        alias="SPLUNKES_MAX_RETRY",
        default=3,
        description="Maximum number of retry attempts for API calls.",
    )
    offset: timedelta = Field(
        alias="SPLUNKES_OFFSET",
        default=timedelta(seconds=30),
        description="Time offset between retry attempts.",
    )
    match_window_before: timedelta = Field(
        alias="SPLUNKES_MATCH_WINDOW_BEFORE",
        default=timedelta(minutes=1),
        description="Slack before the step's start_date when tying an alert to a "
        "step (absorbs clock skew between agent and Splunk).",
    )
    match_window_after: timedelta = Field(
        alias="SPLUNKES_MATCH_WINDOW_AFTER",
        default=timedelta(minutes=5),
        description="Slack after the step's end_date when tying an alert to a "
        "step (correlation searches often stamp alerts a few minutes later).",
    )
    sourcetypes: str = Field(
        alias="SPLUNKES_SOURCETYPES",
        default="*",
        description="Comma-separated sourcetype(s) the wide search is limited to. "
        "'*' searches every sourcetype of the alerts index (slower).",
    )
    alert_delay: timedelta = Field(
        alias="SPLUNKES_ALERT_DELAY",
        default=timedelta(seconds=30),
        description="How long after a step ends its alerts usually take to be "
        "searchable. A step is not searched before this has passed.",
    )
    search_limit: int = Field(
        alias="SPLUNKES_SEARCH_LIMIT",
        default=1000,
        description="Maximum rows a single search returns.",
    )
    memory_path: Optional[str] = Field(
        alias="SPLUNKES_MEMORY_PATH",
        default="splunkes_location_memory.json",
        description="Local file remembering where each test's detection was "
        "found. Empty disables the memory.",
    )
    memory_ttl: timedelta = Field(
        alias="SPLUNKES_MEMORY_TTL",
        default=timedelta(days=30),
        description="A remembered location older than this is dropped and must "
        "be found by a wide search again.",
    )
    memory_wide_every: int = Field(
        alias="SPLUNKES_MEMORY_WIDE_EVERY",
        default=5,
        description="Every Nth run of a test searches wide even when a "
        "remembered location exists (1 = always wide).",
    )
    query_template: Optional[str] = Field(
        alias="SPLUNKES_QUERY_TEMPLATE",
        default=None,
        description="SPL query template with placeholders: {alerts_index}, {source_ips}, "
        "{target_ips}, {start_date}, {end_date}, {process_conditions}, "
        "{ip_conditions} (legacy), {time_window} (legacy). "
        "Must include '| table _time' for proper alert parsing. "
        "Leave empty to use the default query.",
    )
