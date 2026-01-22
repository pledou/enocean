"""Ventilairsec MSC Telegram Parser for EnOcean.

This module provides parsing functionality for Ventilairsec manufacturer-specific
communication (MSC) telegrams using RORG 0xD1079.

The Ventilairsec system uses multiple command IDs (0-8) to organize different
types of data. Each command has a specific structure defined in the EEP.xml file.
"""

from __future__ import annotations

import logging
import struct
from typing import Any

import enocean.utils
from enocean.protocol.eep import EEP

_LOGGER = logging.getLogger(__name__)

# Command ID definitions
CMD_CURRENT_DATA = 0  # Operating data (mode, setpoints, flags)
CMD_CURRENT_SUPPLEMENT_1 = 1  # Flow, power, motor speed
CMD_CURRENT_SUPPLEMENT_2 = 2  # Pressure, filter, external temp
CMD_MAINTENANCE = 3  # Maintenance status, tests, errors
CMD_CONFIGURATION = 4  # Machine configuration
CMD_INTERNAL_SENSORS = 5  # Internal sensors 0-2
CMD_INTERNAL_SENSORS_SUPP = 6  # Internal sensors 3-4
CMD_OPTIONS = 7  # Bypass and valve states
CMD_PAIRED_SENSORS = 8  # Paired sensor information


class VentilairsecParser:
    """Parser for Ventilairsec MSC telegrams."""

    _EEP_RORG = 0xD1  # RORG 0xD1079 => RORG is 0xD1, FUNC 0x07, TYPE 0x09
    _EEP_FUNC = 0x07
    _EEP_TYPE = 0x09
    _EEP = EEP()

    @staticmethod
    def parse_packet(data: bytes) -> dict[str, Any] | None:
        """Parse a Ventilairsec MSC telegram packet.

        Args:
            data: Raw packet data bytes

        Returns:
            Dictionary with parsed fields, or None if parsing fails
        """
        if not data or len(data) < 2:
            _LOGGER.debug("Packet too short: %s bytes", len(data) if data else 0)
            return None

        try:
            # Extract command ID from bits 12-15 (offset 12, size 4)
            # In byte format: byte 1, bits 4-7
            if len(data) < 2:
                return None

            command_id = (data[1] & 0xF0) >> 4

            _LOGGER.debug(
                "Parsing Ventilairsec packet with CMD=%d, length=%d",
                command_id,
                len(data),
            )

            parsed = VentilairsecParser._parse_from_eep(data, command_id)
            if parsed is not None:
                return parsed

            # If dynamic EEP parsing is not available, log and return None
            _LOGGER.debug("No parser available for command ID: %d", command_id)
            return None

        except (ValueError, TypeError, struct.error) as err:
            _LOGGER.error("Error parsing Ventilairsec packet: %s", err)
            return None

    @staticmethod
    def _parse_from_eep(data: bytes, command_id: int) -> dict[str, Any] | None:
        """Parse using dynamic EEP definitions from EEP.xml."""

        # The enocean EEP helper expects bitarrays for data and status like Packet._bit_data.
        byte_values = list(data)

        # Minimum length: RORG + data + sender(4) + status(1) => 6 bytes data payload + 5 = 11
        if len(byte_values) < 11:
            _LOGGER.debug(
                "Ventilairsec EEP parse skipped: packet too short (%d bytes)",
                len(byte_values),
            )
            return None

        try:
            bit_data = enocean.utils.to_bitarray(
                byte_values[1 : len(byte_values) - 5], (len(byte_values) - 6) * 8
            )
            bit_status = enocean.utils.to_bitarray(byte_values[-1])
        except (ValueError, TypeError) as err:
            _LOGGER.debug(
                "Failed to create bitarrays for Ventilairsec EEP parsing: %s", err
            )
            return None

        profile = VentilairsecParser._EEP.find_profile(
            bit_data,
            VentilairsecParser._EEP_RORG,
            VentilairsecParser._EEP_FUNC,
            VentilairsecParser._EEP_TYPE,
            command=command_id,
        )

        if profile is None:
            _LOGGER.debug(
                "Ventilairsec EEP profile not found for command %d", command_id
            )
            return None

        _, values = VentilairsecParser._EEP.get_values(profile, bit_data, bit_status)
        if not values:
            return None

        parsed: dict[str, Any] = {"CMD": command_id}
        for shortcut, payload in values.items():
            # Use raw_value to keep compatibility with enum mapping in HA
            if isinstance(payload, dict) and "raw_value" in payload:
                parsed[shortcut] = payload["raw_value"]
            else:
                parsed[shortcut] = payload

        return parsed


def get_field_value(parsed_data: dict[str, Any], field_name: str) -> Any | None:
    """Get a specific field value from parsed Ventilairsec data.

    Args:
        parsed_data: Dictionary returned by VentilairsecParser.parse_packet()
        field_name: Name of the field to retrieve (e.g., "TEMP0", "MF", "DEBAS")

    Returns:
        Field value if found, None otherwise
    """
    if not parsed_data or not field_name:
        return None

    return parsed_data.get(field_name)
