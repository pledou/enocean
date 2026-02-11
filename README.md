# Python EnOcean Extended

[![PyPI version](https://badge.fury.io/py/enocean-extended.svg)](https://badge.fury.io/py/enocean-extended)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/pypi/pyversions/enocean-extended)](https://pypi.org/project/enocean-extended/)

An enhanced Python library for reading and controlling [EnOcean](http://www.enocean.com/) devices with extended device support and dynamic EEP parsing.

## What's New in This Fork

This is an enhanced version of the original [kipe/enocean](https://github.com/kipe/enocean) library with:

- **Dynamic EEP Parsing**: Improved parsing of complex EnOcean Equipment Profiles with proper enum handling
- **Extended Device Support**: Additional EEP profiles including VentilAirSec ventilation units (D2-50-00, D2-50-01)
- **Enhanced MSC Telegram Support**: Better handling of Manufacturer-Specific Command (MSC) telegrams
- **Improved Enum Values**: Proper parsing of rangeitem enums with min/max values
- **Better Error Handling**: More robust packet parsing and error reporting

Originally started as part of [Forget Me Not](http://www.element14.com/community/community/design-challenges/forget-me-not)
design challenge @ [element14](http://www.element14.com/).

## Installation

Install from PyPI:

```bash
pip install enocean-extended
```

Or install from source for the latest development version:

```bash
pip install git+https://github.com/pledou/enocean.git
```

## Quick Start

After installation, you can run the example script and interact with your EnOcean devices:

```python
import enocean.utils
from enocean.communicators.serialcommunicator import SerialCommunicator
from enocean.protocol.packet import RadioPacket

# Initialize the EnOcean dongle
communicator = SerialCommunicator('/dev/ttyUSB0')
communicator.start()

# Receive packets
for packet in communicator.receive.get(block=True, timeout=1):
    if isinstance(packet, RadioPacket):
        print(packet)
```

See the `examples/` directory for more usage examples, including VentilAirSec ventilation unit control.

## Supported Devices

This library supports a wide range of EnOcean Equipment Profiles (EEPs), including:

- **Sensors**: Temperature, humidity, illumination, occupancy, CO2, etc.
- **Switches**: Rocker switches, push buttons, window handles
- **Actuators**: Light dimmers, blinds, valves
- **Ventilation**: VentilAirSec units with full monitoring and control

For a complete list, see [SUPPORTED_PROFILES.md](SUPPORTED_PROFILES.md).

## Features

### Dynamic EEP Parsing
Automatically parses complex EnOcean Equipment Profiles with proper handling of:
- Enum values with ranges
- Multi-byte values
- Manufacturer-specific commands (MSC)
- Bitfield data

### VentilAirSec Support
Full support for VentilAirSec ventilation units including:
- Operating mode control
- Fan speed adjustment
- Temperature setpoints
- Boost and holiday modes
- Sensor monitoring
- Maintenance status

## Development

To contribute or modify the library:

```bash
git clone https://github.com/pledou/enocean.git
cd enocean
pip install -e .[dev]
pytest
```

## Credits

- **Original Author**: Kimmo Huoman ([kipe/enocean](https://github.com/kipe/enocean))
- **Enhanced Version**: Pierre Leduc with dynamic EEP parsing and extended device support

## License

MIT License - see [LICENSE](LICENSE) file for details.
