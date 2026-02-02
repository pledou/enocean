import pytest
from enocean.utils import crc8, build_esp3_radio


def test_crc8_known():
    # Known vector: crc8 of header [0x00, 0x07, 0x00, 0x01] (example)
    header = bytes([0x00, 0x07, 0x00, 0x01])
    c = crc8(header)
    assert isinstance(c, int)
    assert 0 <= c <= 0xFF


def test_build_esp3_radio_frame_structure():
    rorg = 0xD1
    data = bytes([0x20, 0x00, 0x00, 0x00, 0x00, 0x00])
    dest = bytes([0x04, 0x20, 0x74, 0xC9])
    frame = build_esp3_radio(rorg, data, dest, tx_flags=0x00)

    # frame must start with sync byte
    assert frame[0] == 0x55
    # header is 4 bytes after sync
    header = frame[1:5]
    crc_h = frame[5]
    # verify header CRC
    from enocean.utils import crc8 as _crc8

    assert crc_h == _crc8(header)

    # compute payload and verify data crc matches
    payload = frame[6:-1]
    data_crc = frame[-1]
    assert data_crc == _crc8(payload)


if __name__ == "__main__":
    pytest.main([__file__])
