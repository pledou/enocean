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


# NOTE: This function is deprecated. Use MSCPacket or RadioPacket.create() instead.
# The Packet.build() method already handles ESP3 frame construction with proper
# optional data support. See enocean.protocol.packet.MSCPacket for MSC packets.


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

    # Read ESP3 response frame structure:
    # Start (1) + Header (4) + HeaderCRC (1) + Data (data_len) + Optional (opt_len) + DataCRC (1)

    # Read start byte
    start = ser.read(1)
    if not start:
        return b""
    if start != b"\x55":
        # not an ESP3 frame start; return what we got
        return start + ser.read(ser.in_waiting if hasattr(ser, "in_waiting") else 0)

    # Read header (4 bytes)
    header = ser.read(4)
    if not header or len(header) < 4:
        return b""

    # Read header CRC
    crc_h = ser.read(1)
    if not crc_h:
        return b""

    # Extract data length and optional length from header
    data_len = (header[0] << 8) | header[1]
    opt_len = header[2]

    # Read data + optional + data CRC
    total_payload = data_len + opt_len + 1  # +1 for data CRC
    payload = ser.read(total_payload)

    return start + header + crc_h + (payload or b"")
