#!/usr/bin/env python3
"""Example: build and optionally send ESP3 RADIO_ERP1 frames to a Ventilairsec device.

Usage:
    python examples/esp3_query.py [--port /dev/ttyUSB0] [--cmd 0|2]

This script will print the ESP3 frame hex for the requested command. If --port is
provided the frame will be written to the serial port.
"""

import argparse
from enocean.utils import build_esp3_radio, crc8, send_esp3


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", help="Serial port to send to (optional)")
    p.add_argument(
        "--cmd", type=int, choices=[0, 2], default=2, help="CMD nibble to send"
    )
    args = p.parse_args()

    rorg = 0xD1
    dest = bytes([0x04, 0x20, 0x74, 0xC9])

    # build 6 data bytes like observed in logs; first byte holds cmd nibble at high nibble
    if args.cmd == 0:
        data_bytes = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    else:
        data_bytes = bytes([0x20, 0x00, 0x00, 0x00, 0x00, 0x00])

    frame = build_esp3_radio(rorg, data_bytes, dest, tx_flags=0x00)
    print("ESP3 frame:", frame.hex())

    if args.port:
        import serial

        with serial.Serial(args.port, 57600, timeout=1) as ser:
            print("Sending...")
            send_esp3(ser, frame, read_response=False)
            print("Sent")


if __name__ == "__main__":
    main()
