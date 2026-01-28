"""Generic EEP Profile Parser for EnOcean.

This module provides a generic parsing functionality for any EnOcean EEP profile
using RORG, FUNC, and TYPE identifiers. It dynamically loads profile definitions
from EEP.xml and parses incoming telegrams accordingly.

Example usage:
    parser = Parser(rorg=0xD1, func=0x07, type_=0x09)
    parsed_data = parser.parse_packet(data, command=command_id)
"""

from __future__ import annotations

import logging
from typing import Any

import enocean.utils
from enocean.protocol.eep import get_eep

_LOGGER = logging.getLogger(__name__)


class Parser:
    """Generic parser for EEP profiles."""

    def __init__(self, rorg: int, func: int, type_: int) -> None:
        """Initialize parser with EEP profile identifiers.

        Args:
            rorg: RORG byte (e.g., 0xD1)
            func: FUNC byte (e.g., 0x07)
            type_: TYPE byte (e.g., 0x09)
        """
        self.rorg = rorg
        self.func = func
        self.type = type_
        self._eep = get_eep()

    def parse_packet(
        self,
        data: bytes,
        min_length: int = 11,
        data_start_idx: int = 1,
        status_idx: int = -1,
        command: int | None = None,
    ) -> dict[str, Any] | None:
        """Parse an EEP telegram packet.

        Args:
            data: Raw packet data bytes
            min_length: Minimum packet length required (default: 11)
            data_start_idx: Starting index of data portion (default: 1 for RORG byte)
            status_idx: Index of status byte (default: -1 for last byte)
            command: Optional command/sub-ID parameter for profile lookup

        Returns:
            Dictionary with parsed fields, or None if parsing fails
        """
        if not data or len(data) < min_length:
            _LOGGER.debug(
                "Packet too short: %d bytes (minimum: %d)",
                len(data) if data else 0,
                min_length,
            )
            return None

        try:
            return self._parse_from_eep(data, data_start_idx, status_idx, command)

        except (ValueError, TypeError) as err:
            _LOGGER.error("Error parsing EEP packet: %s", err)
            return None

    def _parse_from_eep(
        self,
        data: bytes,
        data_start_idx: int,
        status_idx: int,
        command: int | None,
    ) -> dict[str, Any] | None:
        """Parse using dynamic EEP definitions from EEP.xml.

        Args:
            data: Raw packet data
            data_start_idx: Starting index of data portion
            status_idx: Index of status byte
            command: Optional command parameter for profile lookup

        Returns:
            Parsed data dictionary or None
        """
        byte_values = list(data)
        data_end_idx = len(byte_values) + status_idx if status_idx < 0 else status_idx

        try:
            # Extract data and status portions
            data_bytes = byte_values[data_start_idx:data_end_idx]
            bit_data = enocean.utils.to_bitarray(data_bytes, len(data_bytes) * 8)
            bit_status = enocean.utils.to_bitarray(byte_values[status_idx])
        except (ValueError, TypeError) as err:
            _LOGGER.debug("Failed to create bitarrays for EEP parsing: %s", err)
            return None

        # Find matching profile
        profile = self._eep.find_profile(
            bit_data,
            self.rorg,
            self.func,
            self.type,
            command=command,
        )

        if profile is None:
            _LOGGER.debug(
                "EEP profile not found for RORG=0x%02X FUNC=0x%02X TYPE=0x%02X%s",
                self.rorg,
                self.func,
                self.type,
                f" CMD={command}" if command is not None else "",
            )
            return None

        _, values = self._eep.get_values(profile, bit_data, bit_status)
        if not values:
            return None

        parsed: dict[str, Any] = {}
        if command is not None:
            parsed["CMD"] = command

        for shortcut, payload in values.items():
            # Use raw_value to keep compatibility with enum mapping
            if isinstance(payload, dict) and "raw_value" in payload:
                parsed[shortcut] = payload["raw_value"]
            else:
                parsed[shortcut] = payload

        return parsed


def get_field_value(parsed_data: dict[str, Any], field_name: str) -> Any | None:
    """Get a specific field value from parsed EEP data.

    Args:
        parsed_data: Dictionary returned by Parser.parse_packet()
        field_name: Name of the field to retrieve (e.g., "TEMP0", "MF", "DEBAS")

    Returns:
        Field value if found, None otherwise
    """
    if not parsed_data or not field_name:
        return None

    return parsed_data.get(field_name)
