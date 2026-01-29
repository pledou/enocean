import logging
from enocean.protocol.parser import Parser


# Enable debug logging for tests
logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.DEBUG)


def make_bytes(hex_list):
    return bytes(int(x, 16) for x in hex_list)


def test_parse_sample_packets_clean():
    """Parse several sample packets from live device logs (2026-01-29 08:40-08:42).

    These packets were captured from a real Ventilairsec device (04:20:58:A5).
    Note: Packets labeled 0x40 are RPS (not BS4) telegrams with embedded data.
    The device appears to send RPS wrappers containing manufacturer-specific payloads.
    All packets should parse without exception.
    """
    # Packets extracted from live device logs, chronologically ordered
    samples = [
        # 2026-01-29 08:40:16.965 - RORG=0x40 (CHAINED Ventilairsec) packet
        (
            [
                "0x40",
                "0x80",
                "0x0",
                "0x11",
                "0xd1",
                "0x7",
                "0x90",
                "0x1",
                "0x2",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4d", "0x0"],
        ),
        # 2026-01-29 08:40:17.058 - RORG=0x40 (CHAINED Ventilairsec) packet
        (
            [
                "0x40",
                "0x81",
                "0x4",
                "0x20",
                "0x1c",
                "0x1c",
                "0x0",
                "0x1",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4f", "0x0"],
        ),
        # 2026-01-29 08:40:17.160 - RORG=0x40 (CHAINED Ventilairsec) packet
        (
            [
                "0x40",
                "0x82",
                "0x0",
                "0x0",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4f", "0x0"],
        ),
        # 2026-01-29 08:40:17.958 - RORG=0xD1 (MSC) Ventilairsec packet, cmd=0x1
        (
            [
                "0xd1",
                "0x7",
                "0x91",
                "0x0",
                "0x5a",
                "0x0",
                "0x4",
                "0x3",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x0",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4f", "0x0"],
        ),
        # 2026-01-29 08:40:18.948 - RORG=0xD1 (MSC) Ventilairsec packet, cmd=0x2
        (
            [
                "0xd1",
                "0x7",
                "0x92",
                "0x6",
                "0x0",
                "0x90",
                "0x18",
                "0x4e",
                "0x6",
                "0xd",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x0",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4f", "0x0"],
        ),
        # 2026-01-29 08:40:19.951 - RORG=0x40 (CHAINED Ventilairsec) - Part 1
        (
            [
                "0x40",
                "0xc0",
                "0x0",
                "0x10",
                "0xd1",
                "0x7",
                "0x93",
                "0x12",
                "0x11",
                "0x10",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4d", "0x0"],
        ),
        # 2026-01-29 08:40:20.062 - RORG=0x40 (CHAINED Ventilairsec) - Part 2
        (
            [
                "0x40",
                "0xc1",
                "0x10",
                "0x1f",
                "0xff",
                "0xff",
                "0xc",
                "0x0",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4f", "0x0"],
        ),
        # 2026-01-29 08:40:20.164 - RORG=0x40 (CHAINED Ventilairsec) - Part 3
        (
            [
                "0x40",
                "0xc2",
                "0x0",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4d", "0x0"],
        ),
        # 2026-01-29 08:40:20.957 - RORG=0x40 (CHAINED Ventilairsec) - Part 1
        (
            [
                "0x40",
                "0x40",
                "0x0",
                "0x10",
                "0xd1",
                "0x7",
                "0x94",
                "0x1",
                "0x1",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4c", "0x0"],
        ),
        # 2026-01-29 08:40:21.060 - RORG=0x40 (CHAINED Ventilairsec) - Part 2
        (
            [
                "0x40",
                "0x41",
                "0xfa",
                "0x18",
                "0xa",
                "0x7",
                "0x61",
                "0x30",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4d", "0x0"],
        ),
        # 2026-01-29 08:40:21.162 - RORG=0x40 (CHAINED Ventilairsec) - Part 3
        (
            [
                "0x40",
                "0x42",
                "0x0",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x50", "0x0"],
        ),
        # 2026-01-29 08:40:21.865 - RORG=0x40 (CHAINED Ventilairsec) - Part 1
        (
            [
                "0x40",
                "0x80",
                "0x0",
                "0x10",
                "0xd1",
                "0x7",
                "0x95",
                "0x0",
                "0x6",
                "0x64",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4d", "0x0"],
        ),
        # 2026-01-29 08:40:22.068 - RORG=0x40 (CHAINED Ventilairsec) - Part 3
        (
            [
                "0x40",
                "0x81",
                "0x1",
                "0x6",
                "0x61",
                "0x2",
                "0x7",
                "0x5b",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4d", "0x0"],
        ),
        # 2026-01-29 08:40:22.162 - RORG=0x40 (RPS) packet
        (
            [
                "0x40",
                "0x82",
                "0x0",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x80",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x50", "0x0"],
        ),
        # 2026-01-29 08:40:22.959 - RORG=0xD1 (MSC) Ventilairsec packet, cmd=0x6
        (
            [
                "0xd1",
                "0x7",
                "0x96",
                "0xff",
                "0x0",
                "0x0",
                "0xff",
                "0x0",
                "0x0",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x0",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4d", "0x0"],
        ),
        # 2026-01-29 08:40:23.950 - RORG=0xD1 (MSC) Ventilairsec packet, cmd=0x7
        (
            [
                "0xd1",
                "0x7",
                "0x97",
                "0x0",
                "0xff",
                "0x0",
                "0xff",
                "0x0",
                "0xff",
                "0x64",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x0",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4d", "0x0"],
        ),
        # 2026-01-29 08:40:24.957 - RORG=0xD1 (MSC) Ventilairsec packet, cmd=0x8
        (
            [
                "0xd1",
                "0x7",
                "0x98",
                "0x4",
                "0x20",
                "0x74",
                "0xc9",
                "0x2",
                "0x1",
                "0x9",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x0",
            ],
            ["0x1", "0xff", "0x9c", "0x80", "0x80", "0x4f", "0x0"],
        ),
        # 2026-01-29 08:41:58.833 - RORG=0xD1 (MSC) Ventilairsec response from 04:20:74:C9, cmd=0x7
        (
            ["0xd1", "0x7", "0x97", "0xaa", "0x4", "0x20", "0x74", "0xc9", "0x0"],
            ["0x1", "0x4", "0x20", "0x58", "0xa5", "0x41", "0x0"],
        ),
        # 2026-01-29 08:41:59.089 - RORG=0xD1 (MSC) Ventilairsec response from 04:20:58:A5, cmd=0x7
        (
            ["0xd1", "0x7", "0x97", "0x55", "0x4", "0x20", "0x58", "0xa5", "0x0"],
            ["0x1", "0x4", "0x20", "0x74", "0xc9", "0x52", "0x0"],
        ),
        # 2026-01-29 08:41:59.248 - RORG=0xD1 (MSC) Ventilairsec echo from 04:20:74:C9, cmd=0x7
        (
            ["0xd1", "0x7", "0x97", "0xaa", "0x4", "0x20", "0x74", "0xc9", "0x0"],
            ["0x1", "0x4", "0x20", "0x58", "0xa5", "0x41", "0x0"],
        ),
        # 2026-01-29 08:41:59.392 - RORG=0xD1 (MSC) Ventilairsec packet from 04:20:74:C9, cmd=0x3
        (
            [
                "0xd1",
                "0x7",
                "0x93",
                "0x6",
                "0x16",
                "0x57",
                "0x3b",
                "0x4",
                "0x20",
                "0x74",
                "0xc9",
                "0x0",
            ],
            ["0x1", "0x4", "0x20", "0x58", "0xa5", "0x41", "0x0"],
        ),
        # 2026-01-29 08:41:59.904 - RORG=0xD1 (MSC) Ventilairsec packet from 04:20:58:A5, cmd=0x0
        (
            [
                "0xd1",
                "0x7",
                "0x90",
                "0x3",
                "0x0",
                "0x82",
                "0x2f",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x0",
            ],
            ["0x1", "0x4", "0x20", "0x74", "0xc9", "0x50", "0x0"],
        ),
        # 2026-01-29 08:42:00.223 - RORG=0xD1 (MSC) Ventilairsec packet from 04:20:58:A5, cmd=0x0 (duplicate)
        (
            [
                "0xd1",
                "0x7",
                "0x90",
                "0x3",
                "0x0",
                "0x82",
                "0x2f",
                "0x4",
                "0x20",
                "0x58",
                "0xa5",
                "0x0",
            ],
            ["0x1", "0x4", "0x20", "0x74", "0xc9", "0x50", "0x0"],
        ),
    ]

    p = Parser(rorg=0xD1079, func=1, type_=0)

    for data_hex, status_hex in samples:
        data = make_bytes(data_hex)
        status = make_bytes(status_hex)
        result = p.parse_packet(data, min_length=1, data_start_idx=0, status_idx=-1)

        assert result is None or isinstance(result, dict)
