"""Splunk ES Service Exceptions.

Custom exceptions for Splunk ES service operations.
"""


class SplunkESServiceError(Exception):
    """Base exception for all Splunk ES service errors."""

    pass


class SplunkESConfigurationError(SplunkESServiceError):
    """Raised when there's a configuration error."""

    pass


class SplunkESExpectationError(SplunkESServiceError):
    """Raised when there's an error processing expectations."""

    pass


class SplunkESFetchError(SplunkESServiceError):
    """Raised when there's an error fetching data from Splunk ES API."""

    pass


class SplunkESMatchingError(SplunkESServiceError):
    """Raised when there's an error matching alerts."""

    pass


class SplunkESNoAlertsFoundError(SplunkESServiceError):
    """Raised when no alerts are found for the search criteria."""

    pass


class SplunkESNoMatchingAlertsError(SplunkESServiceError):
    """Raised when alerts are found but none match the expectation."""

    def __init__(self, *args: object, reason: str = "no_matching_alert") -> None:
        """Keep a machine-readable miss reason next to the message."""
        super().__init__(*args)
        self.reason = reason


class SplunkESDataConversionError(SplunkESServiceError):
    """Raised when there's an error converting data."""

    pass


class SplunkESAPIError(SplunkESServiceError):
    """Raised when there's an error with Splunk ES API operations."""

    pass


class SplunkESNetworkError(SplunkESServiceError):
    """Raised when there's a network connectivity error."""

    pass


class SplunkESSessionError(SplunkESServiceError):
    """Raised when there's an error with session management."""

    pass


class SplunkESQueryError(SplunkESServiceError):
    """Raised when there's an error with query operations."""

    pass


class SplunkESValidationError(SplunkESServiceError):
    """Raised when input validation fails."""

    pass


class SplunkESTimeoutError(SplunkESServiceError):
    """Raised when operations timeout."""

    pass


class SplunkESAuthenticationError(SplunkESServiceError):
    """Raised when authentication fails."""

    pass


class SplunkESIndexNotFoundError(SplunkESServiceError):
    """Raised when the configured alerts index does not exist or is not readable."""

    pass
