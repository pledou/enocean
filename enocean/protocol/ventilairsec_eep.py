"""Ventilairsec EEP field metadata and mappings.

This module builds the field definitions dynamically from the bundled
EEP.xml to stay in sync with the official profile definitions.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from bs4 import BeautifulSoup

_LOGGER = logging.getLogger(__name__)

_EEP_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "EEP.xml")


def _build_enum_map(enum_element) -> dict[int, str]:
    """Create a value-to-description mapping from an <enum> element."""

    enum_map: dict[int, str] = {}

    for item in enum_element.find_all("item", recursive=False):
        try:
            enum_map[int(item["value"])] = item.get("description", "")
        except (KeyError, ValueError):
            continue

    for range_item in enum_element.find_all("rangeitem", recursive=False):
        try:
            start = int(range_item.get("start", -1))
            end = int(range_item.get("end", start))
        except ValueError:
            continue

        for value in range(start, end + 1):
            enum_map[value] = range_item.get("description", "").format(value=value)

    return enum_map


def _load_dynamic_fields() -> dict[str, dict[str, Any]]:
    """Load Ventilairsec field metadata from EEP.xml.

    Returns an empty dictionary if loading or parsing fails.
    """

    try:
        with open(_EEP_PATH, "r", encoding="utf-8") as xml_file:
            soup = BeautifulSoup(xml_file.read(), "xml")
    except OSError as err:
        _LOGGER.warning("Unable to read EEP.xml for Ventilairsec: %s", err)
        return {}

    # Find all Ventilairsec telegrams (RORG 0xD1079)
    telegrams = soup.find_all("telegram", {"rorg": "0xD1079"})
    if not telegrams:
        _LOGGER.warning("Ventilairsec telegram (0xD1079) not found in EEP.xml")
        return {}

    # Find the one with func="0x01"
    profiles = None
    for telegram in telegrams:
        profiles = telegram.find("profiles", {"func": "0x01"})
        if profiles:
            break

    if not profiles:
        _LOGGER.warning("Ventilairsec func 0x01 profiles not found in EEP.xml")
        return {}

    profile = profiles.find("profile", {"type": "0x00"})
    if not profile:
        _LOGGER.warning("Ventilairsec profile type 0x00 not found in EEP.xml")
        return {}

    fields: dict[str, dict[str, Any]] = {}

    for data in profile.find_all("data", recursive=False):
        for element in data.find_all(["enum", "value"], recursive=False):
            shortcut = element.get("shortcut")
            if not shortcut:
                continue

            metadata: dict[str, Any] = {
                "name": element.get("description"),
                "unit": (element.get("unit") or None),
            }

            if element.name == "enum":
                enum_map = _build_enum_map(element)
                if enum_map:
                    metadata["enum_map"] = enum_map

            fields[shortcut] = metadata

    return fields


VENTILAIRSEC_FIELDS = _load_dynamic_fields()


def get_field_metadata(field_shortcut: str) -> dict[str, Any] | None:
    """Get metadata for a Ventilairsec field.

    Args:
        field_shortcut: Field shortcut (e.g., "TEMP0", "MF")

    Returns:
        Dictionary with field metadata or None if field not found
    """
    return VENTILAIRSEC_FIELDS.get(field_shortcut)


def get_field_value_with_enum(
    parsed_data: dict[str, Any], field_shortcut: str
) -> Any | None:
    """Get a field value from parsed data, applying enum mapping if available.

    Args:
        parsed_data: Dictionary from VentilairsecParser.parse_packet()
        field_shortcut: Field shortcut (e.g., "MF")

    Returns:
        Enumerated string if enum mapping exists, raw value otherwise, or None
    """
    value = parsed_data.get(field_shortcut)
    if value is None:
        return None

    metadata = VENTILAIRSEC_FIELDS.get(field_shortcut)
    if metadata and "enum_map" in metadata:
        return metadata["enum_map"].get(value, value)

    return value
