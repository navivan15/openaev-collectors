"""Splunk ES Data Converter.

This module provides conversion functionality for Splunk ES data types.
Handles conversion between different data formats and OAEV data.
"""

import logging
from typing import Any

from .exception import SplunkESDataConversionError, SplunkESValidationError
from .models import SplunkESAlert
from .step_matching import (
    KEY_HOSTS,
    KEY_MARKER_FIELDS,
    KEY_SOURCE,
    KEY_TIME,
    extract_alert_hosts,
    extract_alert_source,
    extract_marker_fields,
)
from .utils.parent_process_parser import ParentProcessParser

LOG_PREFIX = "[SplunkESConverter]"


class Converter:
    """Converter for Splunk ES data to OAEV format."""

    def __init__(self) -> None:
        """Initialize converter with logger.

        Sets up logging for the converter instance.
        """
        self.logger = logging.getLogger(__name__)
        self.parent_process_parser = ParentProcessParser()
        self.logger.debug(f"{LOG_PREFIX} Splunk ES data converter initialized")

    def convert_data_to_oaev_data(
        self,
        data: SplunkESAlert | list[SplunkESAlert] | None,
    ) -> list[dict[str, Any]]:
        """Convert Splunk ES data to OAEV format.

        Args:
            data: Raw Splunk ES alert data.

        Returns:
            List of OAEV data dictionaries.

        Raises:
            SplunkESValidationError: If data format is invalid.
            SplunkESDataConversionError: If conversion fails.

        """
        if not data:
            self.logger.debug(
                f"{LOG_PREFIX} No data provided for conversion, returning empty list"
            )
            return []

        if not isinstance(data, list):
            data = [data]

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Converting {len(data)} Splunk ES alert items to OAEV format"
            )
            oaev_datas = []
            alert_count = 0
            unknown_count = 0

            for i, item in enumerate(data, 1):
                self.logger.debug(f"{LOG_PREFIX} Processing alert item {i}/{len(data)}")

                try:
                    if self._is_alert_data(item):
                        oaev_data = self._alert_data(item)
                        alert_count += 1
                        self.logger.debug(
                            f"{LOG_PREFIX} Converted Splunk ES alert item {i}"
                        )
                    else:
                        unknown_count += 1
                        self.logger.warning(
                            f"{LOG_PREFIX} Unknown data type for item {i}: {type(item)}"
                        )
                        continue

                    if oaev_data:
                        oaev_datas.append(oaev_data)
                        self.logger.debug(
                            f"{LOG_PREFIX} Successfully converted item {i} to OAEV format"
                        )
                    else:
                        self.logger.debug(
                            f"{LOG_PREFIX} Item {i} conversion resulted in empty OAEV data - filtering out"
                        )

                except Exception as e:
                    raise SplunkESDataConversionError(
                        f"Failed to convert data item {i}: {e}"
                    ) from e

            self.logger.info(
                f"{LOG_PREFIX} Splunk ES to OAEV conversion: processed {len(data)} items -> {len(oaev_datas)} results"
            )

            self.logger.info(
                f"{LOG_PREFIX} Conversion completed: {alert_count} alerts, "
                f"{unknown_count} unknown items -> {len(oaev_datas)} OAEV items"
            )
            return oaev_datas

        except SplunkESDataConversionError:
            raise
        except Exception as e:
            raise SplunkESDataConversionError(
                f"Unexpected error converting data to OAEV format: {e}"
            ) from e

    def _is_alert_data(self, data: Any) -> bool:
        """Check if data is Splunk ES alert data.

        Args:
            data: Data object to check.

        Returns:
            True if data is a SplunkESAlert instance.

        """
        return isinstance(data, SplunkESAlert)

    def _alert_data(self, alert_data: SplunkESAlert) -> dict[str, Any]:
        """Convert Splunk ES alert data to OAEV format.

        Args:
            alert_data: Splunk ES alert data.

        Returns:
            OAEV formatted data dictionary.

        Raises:
            SplunkESValidationError: If input type is invalid.
            SplunkESDataConversionError: If conversion fails.

        """
        try:
            oaev_data = {}

            if not isinstance(alert_data, SplunkESAlert):
                raise SplunkESValidationError(
                    f"Invalid input type for alert conversion: {type(alert_data)}"
                )

            source_ips = self._extract_source_ips(alert_data)
            for key, ips in self._split_by_family(source_ips, "source").items():
                oaev_data[key] = {"type": "simple", "data": ips}
                self.logger.debug(f"{LOG_PREFIX} Using {key}: {ips}")

            target_ips = self._extract_target_ips(alert_data)
            for key, ips in self._split_by_family(target_ips, "target").items():
                oaev_data[key] = {"type": "simple", "data": ips}
                self.logger.debug(f"{LOG_PREFIX} Using {key}: {ips}")

            parent_process_name = self._extract_parent_process_name(alert_data)
            if parent_process_name:
                oaev_data["parent_process_name"] = {
                    "type": "fuzzy",
                    "data": [parent_process_name],
                    "score": 95,
                }
                self.logger.debug(
                    f"{LOG_PREFIX} Using parent process name: {parent_process_name}"
                )

            # Step-matching context: event time, host names and the fields
            # that may carry a per-step marker. Kept under "_alert_*" keys so
            # they never collide with OpenAEV signature types.
            raw = alert_data.raw or {}
            hosts = extract_alert_hosts(raw)
            marker_fields = extract_marker_fields(raw)
            if hosts or marker_fields:
                oaev_data[KEY_HOSTS] = hosts
                oaev_data[KEY_MARKER_FIELDS] = marker_fields
            if oaev_data and alert_data.time:
                oaev_data[KEY_TIME] = alert_data.time
            if oaev_data:
                oaev_data[KEY_SOURCE] = extract_alert_source(raw)

            if alert_data.signature:
                self.logger.debug(
                    f"{LOG_PREFIX} Alert includes signature: {alert_data.signature}"
                )

            if alert_data.rule_name:
                self.logger.debug(
                    f"{LOG_PREFIX} Alert includes rule name: {alert_data.rule_name}"
                )

            self.logger.debug(
                f"{LOG_PREFIX} Converted Splunk ES alert to OAEV with {len(oaev_data)} fields"
            )
            return oaev_data if oaev_data else {}

        except SplunkESValidationError:
            raise
        except Exception as e:
            raise SplunkESDataConversionError(
                f"Error converting Splunk ES alert data to OAEV: {e}"
            ) from e

    @staticmethod
    def _split_by_family(ips: list[str], direction: str) -> dict[str, list[str]]:
        """Group IPs into the correct OAEV signature key by address family.

        The OAEV expectation signatures distinguish IPv4 vs IPv6 (e.g.
        ``source_ipv4_address`` vs ``source_ipv6_address``). Emitting every alert
        IP under the IPv4 key made IPv6 detection expectations impossible to
        match (key mismatch). Here we route each address to the matching key so
        both families validate correctly.

        Args:
            ips: Alert IP addresses (may be v4 or v6).
            direction: "source" or "target".

        Returns:
            Mapping of OAEV signature key -> list of addresses of that family.
        """
        out: dict[str, list[str]] = {}
        for ip in ips or []:
            family = "ipv6" if ":" in ip else "ipv4"
            key = f"{direction}_{family}_address"
            out.setdefault(key, []).append(ip)
        return out

    def _extract_source_ips(self, alert_data: SplunkESAlert) -> list[str]:
        """Extract source IP addresses from alert data.

        Args:
            alert_data: SplunkESAlert object.

        Returns:
            List of unique source IP addresses.

        """
        source_ips = []

        if alert_data.src_ip and alert_data.src_ip not in source_ips:
            source_ips.append(alert_data.src_ip)

        return source_ips

    def _extract_target_ips(self, alert_data: SplunkESAlert) -> list[str]:
        """Extract target IP addresses from alert data.

        Args:
            alert_data: SplunkESAlert object.

        Returns:
            List of unique target IP addresses.

        """
        target_ips = []

        if alert_data.dst_ip and alert_data.dst_ip not in target_ips:
            target_ips.append(alert_data.dst_ip)

        return target_ips

    def _extract_parent_process_name(self, alert_data: SplunkESAlert) -> str:
        """Extract parent process name from alert data.

        This method reconstructs the parent process name from the URL path
        found in the alert data.

        Args:
            alert_data: SplunkESAlert object.

        Returns:
            Reconstructed parent process name if UUIDs found in URL path, empty string otherwise.

        """
        if not alert_data.url_path:
            self.logger.debug(f"{LOG_PREFIX} No URL path found in alert data")
            return ""

        try:
            self.logger.debug(
                f"{LOG_PREFIX} Extracting parent process name from URL path: {alert_data.url_path}"
            )

            uuids = self.parent_process_parser.extract_uuids_from_url_path(
                alert_data.url_path
            )
            if uuids:
                inject_uuid, agent_uuid = uuids
                parent_process_name = (
                    self.parent_process_parser.construct_parent_process_name(
                        inject_uuid, agent_uuid
                    )
                )
                self.logger.debug(
                    f"{LOG_PREFIX} Reconstructed parent process name: {parent_process_name}"
                )
                return parent_process_name
            else:
                self.logger.debug(
                    f"{LOG_PREFIX} No UUIDs found in URL path: {alert_data.url_path}"
                )
                return ""
        except Exception as e:
            self.logger.error(f"{LOG_PREFIX} Error extracting parent process name: {e}")
            return ""
