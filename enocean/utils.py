# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import


def get_bit(byte, bit):
    """Get bit value from byte"""
    return (byte >> bit) & 0x01


def combine_hex(data):
    """Combine list of integer values to one big integer"""
    output = 0x00
    for i, value in enumerate(reversed(data)):
        output |= value << i * 8
    return output


def to_bitarray(data, width=8):
    """Convert data (list of integers, bytearray or integer) to bitarray"""
    if isinstance(data, list) or isinstance(data, bytearray):
        data = combine_hex(data)
    return [True if digit == "1" else False for digit in bin(data)[2:].zfill(width)]


def from_bitarray(data):
    """Convert bit array back to integer"""
    if not data:
        return 0
    return int("".join(["1" if x else "0" for x in data]), 2)


def to_hex_string(data):
    """Convert list of integers to a hex string, separated by ":" """
    if isinstance(data, int):
        return "%02X" % data
    return ":".join([("%02X" % o) for o in data])


def from_hex_string(hex_string):
    """Convert hex string (separated by ":") back to list of integers"""
    reval = [int(x, 16) for x in hex_string.split(":")]
    if len(reval) == 1:
        return reval[0]
    return reval


def crc8(data: bytes) -> int:
    """Compute CRC-8 (polynomial 0x07, MSB-first) used by ESP3 frames.

    This implementation returns an 8-bit integer CRC for the input bytes.
    """
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x07) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def build_esp3_radio(rorg: int, data: bytes, dest: bytes, tx_flags: int = 0) -> bytes:
    """Build an ESP3 RADIO_ERP1 frame.

    Args:
        rorg: RORG byte (e.g. 0xD1)
        data: data bytes payload (device-specific)
        dest: 4-byte destination id (device address)
        tx_flags: single byte tx flags appended after dest (default 0)

    Returns:
        Raw ESP3 frame bytes ready to write to serial
    """
    if not isinstance(dest, (bytes, bytearray)) or len(dest) != 4:
        raise ValueError("dest must be 4 bytes")

    payload = bytes([rorg]) + bytes(data) + bytes(dest) + bytes([tx_flags & 0xFF])

    data_len = len(payload)
    opt_len = 0
    packet_type = 0x01  # RADIO_ERP1

    header = bytes([(data_len >> 8) & 0xFF, data_len & 0xFF, opt_len, packet_type])
    crc_h = crc8(header)

    frame = b"\x55" + header + bytes([crc_h]) + payload + bytes([crc8(payload)])
    return frame


def send_esp3(
    ser, frame: bytes, read_response: bool = False, timeout: float = 1.0
) -> bytes | None:
    """Send an ESP3 frame over an opened serial-like object.

    The `ser` object must implement `.write(bytes)` and, if `read_response` is True,
    `.read(size)` or `.readinto` and have a `timeout` behavior.

    Returns response bytes if `read_response` is True and data is available, otherwise None.
    """
    ser.write(frame)
    if not read_response:
        return None
    # best-effort read: read header (1 + 4 + 1 = start + header + crc)
    # Wait a short time for device to respond; rely on serial timeout
    # Read start byte
    start = ser.read(1)
    if not start:
        return b""
    if start != b"\x55":
        # not an ESP3 frame start; return what we got
        return start + ser.read(ser.in_waiting if hasattr(ser, "in_waiting") else 0)
    header = ser.read(4)
    crc_h = ser.read(1)
    if not header or not crc_h:
        return b""
    # compute payload length
    data_len = (header[0] << 8) | header[1]
    payload = ser.read(data_len + 1)  # payload + data crc
    return start + header + crc_h + (payload or b"")
