# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
from collections import OrderedDict

import enocean.utils
from enocean.protocol import crc8
from enocean.protocol.eep import get_eep
from enocean.protocol.constants import (
    PACKET,
    RORG,
    PARSE_RESULT,
    DB0,
    DB2,
    DB3,
    DB4,
    DB6,
)

# Global storage for chained telegrams
_CHAINED_STORAGE = {}


class _LazyEEPProxy:
    """Proxy that delegates attribute access to the real EEP instance.

    This avoids instantiating the EEP parser (which opens EEP.xml) at
    import time. The real EEP is created on first attribute access.
    """

    def __getattr__(self, item):
        return getattr(get_eep(), item)


class Packet(object):
    """
    Base class for Packet.
    Mainly used for for packet generation and
    Packet.parse_msg(buf) for parsing message.
    parse_msg() returns subclass, if one is defined for the data type.
    """

    eep = _LazyEEPProxy()
    logger = logging.getLogger("enocean.protocol.packet")

    def __init__(self, packet_type, data=None, optional=None):
        """Initialize a Packet instance.

        Args:
            packet_type: Packet type identifier (from PACKET enum).
            data: Optional list of data bytes for the packet.
            optional: Optional list of optional bytes for the packet.
        """
        self.packet_type = packet_type
        self.rorg = RORG.UNDEFINED
        self.rorg_func = None
        self.rorg_type = None
        self.rorg_manufacturer = None

        self.received = None

        if data is None or not isinstance(data, list):
            self.logger.warning("Replacing Packet.data with default value.")
            self.data = []
        else:
            self.data = data

        if optional is None:
            self.optional = []
        elif not isinstance(optional, list):
            self.logger.warning("Replacing Packet.optional with default value.")
            self.optional = []
        else:
            self.optional = optional

        self.status = 0
        self.parsed = OrderedDict({})
        self.repeater_count = 0
        self._profile = None

        self.parse()

    def __str__(self):
        """Return a concise string representation for the packet."""
        return "0x%02X %s %s %s" % (
            self.packet_type,
            [hex(o) for o in self.data],
            [hex(o) for o in self.optional],
            self.parsed,
        )

    def __unicode__(self):
        """Return the string representation (for Python 2 compatibility)."""
        return self.__str__()

    def __eq__(self, other):
        """Return True if two Packet instances are equal in type and content."""
        return (
            self.packet_type == other.packet_type
            and self.rorg == other.rorg
            and self.data == other.data
            and self.optional == other.optional
        )

    @property
    def _bit_data(self):
        """Return the packet's data payload as a bitarray.

        The first and last five bytes are protocol control bytes and are not
        included in the returned bitarray.
        """
        return enocean.utils.to_bitarray(
            self.data[1 : len(self.data) - 5], (len(self.data) - 6) * 8
        )

    @_bit_data.setter
    def _bit_data(self, value):
        """Set the packet's data payload from a bitarray value.

        The supplied bitarray is split into bytes and stored into the
        internal `data` list, leaving protocol control bytes untouched.
        """
        for byte in range(len(self.data) - 6):
            self.data[byte + 1] = enocean.utils.from_bitarray(
                value[byte * 8 : (byte + 1) * 8]
            )

    # # COMMENTED OUT, AS NOTHING TOUCHES _bit_optional FOR NOW.
    # # Thus, this is also untested.
    # @property
    # def _bit_optional(self):
    #     return enocean.utils.to_bitarray(self.optional, 8 * len(self.optional))

    # @_bit_optional.setter
    # def _bit_optional(self, value):
    #     if self.rorg in [RORG.RPS, RORG.BS1]:
    #         self.data[1] = enocean.utils.from_bitarray(value)
    #     if self.rorg == RORG.BS4:
    #         for byte in range(4):
    #             self.data[byte+1] = enocean.utils.from_bitarray(value[byte*8:(byte+1)*8])

    @property
    def _bit_status(self):
        """Return the status byte represented as a bitarray."""
        return enocean.utils.to_bitarray(self.status)

    @_bit_status.setter
    def _bit_status(self, value):
        """Set the status byte from a bitarray value."""
        self.status = enocean.utils.from_bitarray(value)

    @property
    def profile(self):
        """Return the EEP profile."""
        return self._profile

    @staticmethod
    def parse_msg(buf):
        """
        Parses message from buffer.
        returns:
            - PARSE_RESULT
            - remaining buffer
            - Packet -object (if message was valid, else None)
        """
        # If the buffer doesn't contain 0x55 (start char)
        # the message isn't needed -> ignore
        if 0x55 not in buf:
            return PARSE_RESULT.INCOMPLETE, [], None

        # Valid buffer starts from 0x55
        # Convert to list, as index -method isn't defined for bytearray
        buf = [
            ord(x) if not isinstance(x, int) else x
            for x in buf[list(buf).index(0x55) :]
        ]
        try:
            data_len = (buf[1] << 8) | buf[2]
            opt_len = buf[3]
        except IndexError:
            # If the fields don't exist, message is incomplete
            return PARSE_RESULT.INCOMPLETE, buf, None

        # Header: 6 bytes, data, optional data and data checksum
        msg_len = 6 + data_len + opt_len + 1
        if len(buf) < msg_len:
            # If buffer isn't long enough, the message is incomplete
            return PARSE_RESULT.INCOMPLETE, buf, None

        msg = buf[0:msg_len]
        buf = buf[msg_len:]

        packet_type = msg[4]
        data = msg[6 : 6 + data_len]
        opt_data = msg[6 + data_len : 6 + data_len + opt_len]

        # Check CRCs for header and data
        if msg[5] != crc8.calc(msg[1:5]):
            # Fail if doesn't match message
            Packet.logger.error("Header CRC error!")
            # Return CRC_MISMATCH
            return PARSE_RESULT.CRC_MISMATCH, buf, None
        if msg[6 + data_len + opt_len] != crc8.calc(msg[6 : 6 + data_len + opt_len]):
            # Fail if doesn't match message
            Packet.logger.error("Data CRC error!")
            # Return CRC_MISMATCH
            return PARSE_RESULT.CRC_MISMATCH, buf, None

        # If we got this far, everything went ok (?)
        if packet_type == PACKET.RADIO_ERP1:
            # Need to handle UTE Teach-in here, as it's a separate packet type...
            if data[0] == RORG.UTE:
                packet = UTETeachInPacket(packet_type, data, opt_data)
            elif data[0] == RORG.CHAINED or data[0] == RORG.CHAINED_VENTILAIRSEC:
                packet = ChainedPacket(packet_type, data, opt_data)
            else:
                packet = RadioPacket(packet_type, data, opt_data)
        elif packet_type == PACKET.RESPONSE:
            packet = ResponsePacket(packet_type, data, opt_data)
        elif packet_type == PACKET.EVENT:
            packet = EventPacket(packet_type, data, opt_data)
        else:
            packet = Packet(packet_type, data, opt_data)

        # Filter out incomplete CHAINED packets (parsed OrderedDict is empty)
        # They should not be propagated until they are fully reassembled into complete MSC packets
        if isinstance(packet, ChainedPacket) and not packet.parsed:
            return PARSE_RESULT.OK, buf, None

        return PARSE_RESULT.OK, buf, packet

    @staticmethod
    def create(
        packet_type,
        rorg,
        rorg_func,
        rorg_type,
        direction=None,
        command=None,
        destination=None,
        sender=None,
        learn=False,
        **kwargs,
    ):
        """
        Creates an packet ready for sending.
        Uses rorg, rorg_func and rorg_type to determine the values set based on EEP.
        Additional arguments (**kwargs) are used for setting the values.

        Currently only supports:
            - PACKET.RADIO_ERP1
            - RORGs RPS, BS1, BS4, VLD.

        TODO:
            - Require sender to be set? Would force the "correct" sender to be set.
            - Do we need to set telegram control bits?
              Might be useful for acting as a repeater?
        """

        if packet_type != PACKET.RADIO_ERP1:
            # At least for now, only support PACKET.RADIO_ERP1.
            raise ValueError("Packet type not supported by this function.")

        if rorg not in [RORG.RPS, RORG.BS1, RORG.BS4, RORG.VLD]:
            # At least for now, only support these RORGS.
            raise ValueError("RORG not supported by this function.")

        if destination is None:
            Packet.logger.warning("Replacing destination with broadcast address.")
            destination = [0xFF, 0xFF, 0xFF, 0xFF]

        # TODO: Should use the correct Base ID as default.
        #       Might want to change the sender to be an offset from the actual address?
        if sender is None:
            Packet.logger.warning("Replacing sender with default address.")
            sender = [0xDE, 0xAD, 0xBE, 0xEF]

        if not isinstance(destination, list) or len(destination) != 4:
            raise ValueError("Destination must a list containing 4 (numeric) values.")

        if not isinstance(sender, list) or len(sender) != 4:
            raise ValueError("Sender must a list containing 4 (numeric) values.")

        packet = Packet(packet_type, data=[], optional=[])
        packet.rorg = rorg
        packet.data = [packet.rorg]
        # Select EEP at this point, so we know how many bits we're dealing with (for VLD).
        packet.select_eep(rorg_func, rorg_type, direction, command)

        # Initialize data depending on the profile.
        if rorg in [RORG.RPS, RORG.BS1]:
            packet.data.extend([0])
        elif rorg == RORG.BS4:
            packet.data.extend([0, 0, 0, 0])
        else:
            packet.data.extend([0] * int(packet.profile.get("bits", "1")))
        packet.data.extend(sender)
        packet.data.extend([0])
        # Always use sub-telegram 3, maximum dbm (as per spec, when sending),
        # and no security (security not supported as per EnOcean Serial Protocol).
        packet.optional = [3] + destination + [0xFF] + [0]

        if command:
            # Set CMD to command, if applicable.. Helps with VLD.
            kwargs["CMD"] = command

        packet.set_eep(kwargs)
        if rorg in [RORG.BS1, RORG.BS4] and not learn:
            if rorg == RORG.BS1:
                packet.data[1] |= 1 << 3
            if rorg == RORG.BS4:
                packet.data[4] |= 1 << 3
        packet.data[-1] = packet.status

        # Parse the built packet, so it corresponds to the received packages
        # For example, stuff like RadioPacket.learn should be set.
        packet = Packet.parse_msg(packet.build())[2]
        packet.rorg = rorg
        packet.parse_eep(rorg_func, rorg_type, direction, command)
        return packet

    def parse(self):
        """Parse data from Packet"""
        # Parse status from messages
        if self.rorg in [RORG.RPS, RORG.BS1, RORG.BS4]:
            self.status = self.data[-1]
        if self.rorg == RORG.VLD:
            self.status = self.optional[-1]

        if self.rorg in [RORG.RPS, RORG.BS1, RORG.BS4]:
            # These message types should have repeater count in the last for bits of status.
            self.repeater_count = enocean.utils.from_bitarray(self._bit_status[4:])
        return self.parsed

    def select_eep(self, rorg_func, rorg_type, direction=None, command=None):
        """Set EEP based on FUNC and TYPE"""
        # set EEP profile
        self.rorg_func = rorg_func
        self.rorg_type = rorg_type

        # For MSC Ventilairsec, EEP.xml uses rorg="0xD1079" which is
        # the concatenation of RORG byte (0xD1) + manufacturer ID (0x079)
        # We need to construct this value: (0xD1 << 12) | manufacturer_bits
        eep_rorg = self.rorg
        if self.rorg == RORG.MSC and hasattr(self, "rorg_manufacturer"):
            # Construct full rorg value for Ventilairsec: 0xD1079 = (0xD1 << 12) | 0x079
            # rorg_manufacturer contains bits 0-12, where bits 0-8 are the RORG byte
            # We need to combine RORG byte with the next bits to match EEP.xml
            manufacturer_bits = self.rorg_manufacturer & 0xFFF  # Keep only 12 bits
            eep_rorg = (self.rorg << 12) | manufacturer_bits

        self._profile = self.eep.find_profile(
            self._bit_data, eep_rorg, rorg_func, rorg_type, direction, command
        )
        return self._profile is not None

    def parse_eep(self, rorg_func=None, rorg_type=None, direction=None, command=None):
        """Parse EEP based on FUNC and TYPE"""
        # set EEP profile, if demanded
        if rorg_func is not None and rorg_type is not None:
            self.select_eep(rorg_func, rorg_type, direction, command)
        # parse data
        provides, values = self.eep.get_values(
            self._profile, self._bit_data, self._bit_status
        )
        self.parsed.update(values)
        return list(provides)

    def set_eep(self, data):
        """Update packet data based on EEP. Input data is a dictionary with keys corresponding to the EEP."""
        self._bit_data, self._bit_status = self.eep.set_values(
            self._profile, self._bit_data, self._bit_status, data
        )

    def build(self):
        """Build Packet for sending to EnOcean controller"""
        data_length = len(self.data)
        ords = [
            0x55,
            (data_length >> 8) & 0xFF,
            data_length & 0xFF,
            len(self.optional),
            int(self.packet_type),
        ]
        ords.append(crc8.calc(ords[1:5]))
        ords.extend(self.data)
        ords.extend(self.optional)
        ords.append(crc8.calc(ords[6:]))
        return ords


class RadioPacket(Packet):
    """Represents a radio ERP1 packet with sender/destination information.

    Extends the base Packet class with radio-specific fields including sender and
    destination IDs, signal strength (dBm), and learn mode flags. Handles parsing
    of bidirectional and unidirectional radio telegrams.
    """

    destination = [0xFF, 0xFF, 0xFF, 0xFF]
    dBm = 0
    sender = [0xFF, 0xFF, 0xFF, 0xFF]
    learn = True
    contains_eep = False

    def __str__(self):
        """Return a human-readable representation of the radio packet.

        Includes sender, destination and signal strength information.
        """
        packet_str = super(RadioPacket, self).__str__()
        return (
            f"{self.sender_hex}->{self.destination_hex} ({self.dBm} dBm): {packet_str}"
        )

    @staticmethod
    def create(
        rorg,
        rorg_func,
        rorg_type,
        direction=None,
        command=None,
        destination=None,
        sender=None,
        learn=False,
        **kwargs,
    ):
        """Create a `Packet` instance for a radio ERP1 telegram.

        This is a thin wrapper around `Packet.create` that sets
        the `packet_type` to `PACKET.RADIO_ERP1`.
        """
        return Packet.create(
            PACKET.RADIO_ERP1,
            rorg,
            rorg_func,
            rorg_type,
            direction,
            command,
            destination,
            sender,
            learn,
            **kwargs,
        )

    @property
    def sender_int(self):
        """Return the sender ID as an integer."""
        return enocean.utils.combine_hex(self.sender)

    @property
    def sender_hex(self):
        """Return the sender ID as a hex string (colon separated)."""
        return enocean.utils.to_hex_string(self.sender)

    @property
    def destination_int(self):
        """Return the destination ID as an integer."""
        return enocean.utils.combine_hex(self.destination)

    @property
    def destination_hex(self):
        """Return the destination ID as a hex string (colon separated)."""
        return enocean.utils.to_hex_string(self.destination)

    def parse(self):
        """Parse radio packet common fields and delegate to base parser.

        Sets `destination`, `dBm`, `sender`, `learn` flag and rorg-specific
        EEP detection before calling the parent `parse` implementation.
        """
        self.destination = self.optional[1:5]
        self.dBm = -self.optional[5]
        self.sender = self.data[-5:-1]
        # Default to learn == True, as some devices don't have a learn button
        self.learn = True

        self.rorg = self.data[0]
        self.cmd = None

        if self.rorg == RORG.VLD and len(self.data) > 1:
            # Common VLD command is in bits 4-7 of the first data byte (offset 0 in data portion)
            self.cmd = enocean.utils.from_bitarray(self._bit_data[8:12])

        if self.rorg == RORG.MSC:
            # MSC telegram: extract manufacturer and command bits
            self.rorg_manufacturer = enocean.utils.from_bitarray(self._bit_data[0:12])
            manufacturer_hex = f"0x{self.rorg_manufacturer:03x}"
            if manufacturer_hex in ("0xd1079", "0x079", "0x79", "0x121"):
                # Ventilairsec: 4-bit command at offset 12 defines func
                self.cmd = enocean.utils.from_bitarray(self._bit_data[12:16])
            else:
                # Fallback: use 8-bit command starting at bit 16
                self.cmd = enocean.utils.from_bitarray(self._bit_data[16:24])

            # For MSC, func and type should have been read from UTE Teach-In
            self.contains_eep = False

        # parse learn bit and FUNC/TYPE, if applicable
        if self.rorg == RORG.BS1:
            self.learn = not self._bit_data[DB0.BIT_3]
        if self.rorg == RORG.BS4:
            self.learn = not self._bit_data[DB0.BIT_3]
            if self.learn:
                self.contains_eep = self._bit_data[DB0.BIT_7]
                if self.contains_eep:
                    # Get rorg_func and rorg_type from an unidirectional learn packet
                    self.rorg_func = enocean.utils.from_bitarray(
                        self._bit_data[DB3.BIT_7 : DB3.BIT_1]
                    )
                    self.rorg_type = enocean.utils.from_bitarray(
                        self._bit_data[DB3.BIT_1 : DB2.BIT_2]
                    )
                    self.rorg_manufacturer = enocean.utils.from_bitarray(
                        self._bit_data[DB2.BIT_2 : DB0.BIT_7]
                    )
                    self.logger.debug(
                        "learn received, EEP detected, RORG: 0x%02X, FUNC: 0x%02X, TYPE: 0x%02X, Manufacturer: 0x%03X",
                        self.rorg,
                        self.rorg_func,
                        self.rorg_type,
                        self.rorg_manufacturer,
                    )

        return super(RadioPacket, self).parse()


class UTETeachInPacket(RadioPacket):
    """Represents a UTE (Unidirectional Teach-in) packet for EnOcean devices.

    Handles bidirectional and unidirectional teach-in requests, including
    device addition, deletion, and EEP profile exchange.
    """

    # Request types
    TEACH_IN = 0b00
    DELETE = 0b01
    NOT_SPECIFIC = 0b10

    # Response types
    NOT_ACCEPTED = [False, False]
    TEACHIN_ACCEPTED = [False, True]
    DELETE_ACCEPTED = [True, False]
    EEP_NOT_SUPPORTED = [True, True]

    unidirectional = False
    response_expected = False
    number_of_channels = 0xFF
    rorg_of_eep = RORG.UNDEFINED
    request_type = NOT_SPECIFIC
    channel = None

    contains_eep = True

    @property
    def bidirectional(self):
        """Return whether the teach-in packet is bidirectional."""
        return not self.unidirectional

    @property
    def teach_in(self):
        """Return True if this request is a teach-in request."""
        return self.request_type != self.DELETE

    @property
    def delete(self):
        """Return True if this request is a delete request."""
        return self.request_type == self.DELETE

    def parse(self):
        """Parse UTE teach-in packet fields and update teach-in attributes.

        Extracts flags (unidirectional, response_expected), request type,
        manufacturer, channel and EEP identifiers when present.
        """
        super(UTETeachInPacket, self).parse()
        self.unidirectional = not self._bit_data[DB6.BIT_7]
        self.response_expected = not self._bit_data[DB6.BIT_6]
        self.request_type = enocean.utils.from_bitarray(
            self._bit_data[DB6.BIT_5 : DB6.BIT_3]
        )
        self.cmd = self.request_type
        self.rorg_manufacturer = enocean.utils.from_bitarray(
            self._bit_data[DB3.BIT_2 : DB2.BIT_7]
            + self._bit_data[DB4.BIT_7 : DB3.BIT_7]
        )  # noqa: E501
        self.channel = self.data[2]
        self.rorg_type = self.data[5]
        self.rorg_func = self.data[6]
        self.rorg_of_eep = self.data[7]
        if self.teach_in:
            self.learn = True

        # Enhanced debug logging for UTE packets
        request_type_name = {
            self.TEACH_IN: "TEACH_IN",
            self.DELETE: "DELETE",
            self.NOT_SPECIFIC: "NOT_SPECIFIC",
        }.get(self.request_type, f"UNKNOWN(0x{self.request_type:02X})")

        self.logger.debug(
            "UTETeachInPacket.parse() - sender=%s, direction=%s, request_type=%s, response_expected=%s",
            self.sender_hex,
            "UNIDIRECTIONAL" if self.unidirectional else "BIDIRECTIONAL",
            request_type_name,
            self.response_expected,
        )
        self.logger.debug(
            "UTE EEP info - RORG=0x%02X, FUNC=0x%02X, TYPE=0x%02X, Manufacturer=0x%03X, Channel=%d",
            self.rorg_of_eep,
            self.rorg_func,
            self.rorg_type,
            self.rorg_manufacturer,
            self.channel,
        )

        return self.parsed

    def create_response_packet(self, sender_id, response=None):
        """Create a RadioPacket response for this teach-in request.

        Args:
            sender_id: Sender ID (4 byte list) to use in the response.
            response: Optional response code list (2 booleans) to indicate acceptance.
        Returns a `RadioPacket` configured as the teach-in response.
        """
        # Create data:
        # - Respond with same RORG (UTE Teach-in)
        # - Always use bidirectional communication, set response code, set command identifier.
        # - Databytes 5 to 0 are copied from the original message
        # - Set sender id and status
        if response is None:
            response = self.TEACHIN_ACCEPTED

        # Validate sender_id - must be a list with 4 bytes
        if not isinstance(sender_id, list) or len(sender_id) != 4:
            self.logger.warning(
                "Invalid sender_id for response packet, using broadcast"
            )
            sender_id = [0xFF, 0xFF, 0xFF, 0xFF]

        data = (
            [self.rorg]
            + [
                enocean.utils.from_bitarray(
                    [True, False] + response + [False, False, False, True]
                )
            ]
            + self.data[2:8]
            + sender_id
            + [0]
        )

        # Always use 0x03 to indicate sending, attach sender ID, dBm, and security level
        optional = [0x03] + self.sender + [0xFF, 0x00]

        return RadioPacket(PACKET.RADIO_ERP1, data=data, optional=optional)


class ResponsePacket(Packet):
    """Represents a response packet from EnOcean controller."""

    response = 0
    response_data = []

    def parse(self):
        """Parse controller response packet fields.

        Extracts the response code and payload into attributes and calls
        the base class parser for any additional processing.
        """
        self.response = self.data[0]
        self.response_data = self.data[1:]

        # Enhanced debug logging for response packets
        response_names = {
            0x00: "OK",
            0x01: "ERROR",
            0x02: "NOT_SUPPORTED",
            0x03: "WRONG_PARAM",
            0x04: "OPERATION_DENIED",
        }
        response_name = response_names.get(
            self.response, f"UNKNOWN(0x{self.response:02X})"
        )

        self.logger.debug(
            "ResponsePacket.parse() - response=0x%02X (%s), data=%s",
            self.response,
            response_name,
            [hex(b) for b in self.response_data[: min(len(self.response_data), 8)]],
        )

        return super(ResponsePacket, self).parse()


class EventPacket(Packet):
    """Represents an event packet from EnOcean controller."""

    event = 0
    event_data = []

    def parse(self):
        """Parse event packet fields.

        Extracts an event identifier and its data and defers to the base parser
        afterwards.
        """
        self.event = self.data[0]
        self.event_data = self.data[1:]
        return super(EventPacket, self).parse()


class MSCPacket(RadioPacket):
    """Manufacturer Specific Communication (MSC) packet.

    MSC packets use RORG 0xD1 and contain manufacturer-specific data.
    This class provides constructors for creating MSC packets for supported manufacturers.
    """

    def __init__(
        self,
        manufacturer,
        command,
        destination=None,
        sender=None,
        **kwargs,
    ):
        """Create an MSC packet for the specified manufacturer.

        Args:
            manufacturer: Manufacturer ID (e.g., 0x079 for VentilAirSec)
            command: Command nibble (0-15, manufacturer-specific)
            destination: Destination address as 4-byte list (default: broadcast)
            sender: Sender address as 4-byte list (required)
            **kwargs: Manufacturer/command-specific field values

        Raises:
            ValueError: If sender is missing or manufacturer not supported
        """
        if sender is None:
            raise ValueError("Sender address is required for MSC packets")

        if destination is None:
            self.logger.warning("Replacing destination with broadcast address.")
            destination = [0xFF, 0xFF, 0xFF, 0xFF]

        if not isinstance(destination, list) or len(destination) != 4:
            raise ValueError(
                "Destination must be a list containing 4 (numeric) values."
            )

        if not isinstance(sender, list) or len(sender) != 4:
            raise ValueError("Sender must be a list containing 4 (numeric) values.")

        # Build packet data based on manufacturer
        if manufacturer in (0x079, 0x79):
            data, optional = self._build_ventilairsec_data(
                command, destination, sender, **kwargs
            )
        else:
            raise ValueError(f"MSC manufacturer 0x{manufacturer:03x} not supported yet")

        # Initialize parent RadioPacket with constructed data
        super().__init__(PACKET.RADIO_ERP1, data=data, optional=optional)

        # Set MSC-specific attributes
        self.rorg = 0xD1
        self.rorg_manufacturer = manufacturer
        self.cmd = command

    def _build_ventilairsec_data(self, command, destination, sender, **kwargs):
        """Build packet data for VentilAirSec VMI devices.

        VentilAirSec uses manufacturer ID 0x079 and command structure:
        - Byte 0: 0xD1 (RORG for MSC)
        - Byte 1: 0x07 (high byte of manufacturer ID)
        - Byte 2: 0x90 + CMD (low byte with command in high nibble)
        - Bytes 3-N: Data fields depending on CMD
        - Last 5 bytes: sender ID + status (0x80)

        CMD=0: Control command with fields:
            MODEFONC, FONC, VACS, BOOST, TEMPEL, TEMPSOUF, TEMPHYD, TEMPSOL, COMMAND
        CMD=1: Hour setting (HOUR data)
        CMD=2: Agenda setting (AGENDA data)

        Returns:
            Tuple of (data, optional) byte arrays
        """
        data = [0xD1]  # RORG for MSC

        if command == 0:
            # CMD=0: Control command
            data.extend([0x07, 0x90])

            # Add fields in order, use 0xFF for missing fields
            field_order = [
                "MODEFONC",
                "FONC",
                "VACS",
                "BOOST",
                "TEMPEL",
                "TEMPSOUF",
                "TEMPHYD",
                "TEMPSOL",
                "COMMAND",
            ]

            for field in field_order:
                if field in kwargs and kwargs[field] is not None:
                    value = kwargs[field]
                    # FONC is binary string, others are integers
                    if field == "FONC" and isinstance(value, str):
                        data.append(int(value, 2))
                    else:
                        # Convert to int and ensure it's in valid range
                        int_value = int(value)
                        if int_value < 0 or int_value > 255:
                            self.logger.warning(
                                "Field %s value %d out of range, clamping",
                                field,
                                int_value,
                            )
                            int_value = max(0, min(255, int_value))
                        data.append(int_value)
                else:
                    # Missing field = 0xFF
                    data.append(0xFF)

        elif command == 1:
            # CMD=1: Hour setting
            data.extend([0x07, 0x91])
            if "HOUR" in kwargs:
                hour_data = kwargs["HOUR"]
                if isinstance(hour_data, str):
                    hour_bytes = bytes.fromhex(hour_data)
                    data.extend(hour_bytes)
                else:
                    data.extend(hour_data)

        elif command == 2:
            # CMD=2: Agenda setting
            data.extend([0x07, 0x92])
            if "AGENDA" in kwargs:
                agenda_data = kwargs["AGENDA"]
                if isinstance(agenda_data, str):
                    agenda_bytes = bytes.fromhex(agenda_data)
                    data.extend(agenda_bytes)
                else:
                    data.extend(agenda_data)
        else:
            raise ValueError(f"VentilAirSec command {command} not supported")

        # Add sender and status byte
        data.extend(sender)
        data.append(0x80)  # Status byte

        # Build optional data: sub-telegram, destination, dBm, security
        # VentilAirSec devices expect broadcast address in optional data
        # The actual destination is implicit from the context/pairing
        optional = [0x03] + [0xFF, 0xFF, 0xFF, 0xFF] + [0xFF, 0x00]

        self.logger.debug(
            "Built VentilAirSec MSC packet: CMD=%d, data_len=%d, data=%s",
            command,
            len(data),
            " ".join(f"0x{b:02x}" for b in data),
        )

        return data, optional


class ChainedPacket(RadioPacket):
    """Handles CHAINED telegrams (RORG 0xC8 or 0x40) for multi-part messages.

    Ventilairsec MSC devices use chained telegrams (proprietary 0x40) to send long
    messages that don't fit in a single EnOcean frame. Standard EnOcean also uses
    0xC8 for chained messages. This class reconstructs the complete message from
    multiple chained frames for both formats.
    """

    def parse(self):
        """Parse chained telegram structure."""
        # Extract basic RadioPacket fields
        self.destination = self.optional[1:5]
        self.dBm = -self.optional[5]
        self.sender = self.data[-5:-1]
        self.learn = True

        self.rorg = self.data[0]

        # Ventilairsec proprietary CHAINED (0x40) uses an alternate
        # framing where continuation payload bytes start at index 2 and
        # the total length is encoded as concatenated decimal strings
        # in bytes 2..3 of the first frame. Use the user-supplied
        # reassembly algorithm for RORG 0x40.
        if self.rorg == RORG.CHAINED_VENTILAIRSEC:
            # Use same bit mapping as standard CHAINED packets:
            # Bits 4-7: sequence, Bits 0-3: index
            byte1 = self.data[1]
            seq = (byte1 >> 4) & 0x0F
            idx = byte1 & 0x0F

            sender_hex = enocean.utils.to_hex_string(self.sender).replace(":", "")
            key = f"{sender_hex}.{seq}"

            if idx == 0:
                # First frame: total length is stored in bytes 2-3 as
                # concatenated decimal strings (e.g., 0x00 0x11 = "0" + "17" = "017" = 17)
                lendata = int(str(self.data[2]) + str(self.data[3]))

                self.logger.info(
                    "Chained telegram: First message (seq=%d), total_length=%d bytes",
                    seq,
                    lendata,
                )

                first_data = self.data[4:-5]
                _CHAINED_STORAGE[key] = {
                    "seq": seq,
                    "total_len": lendata,
                    "data": list(first_data),
                    "sender": self.sender,
                    "optional": self.optional,
                }

                self.parsed = OrderedDict()
                return self.parsed

            # continuation
            self.logger.debug(
                "Chained telegram: Continuation (seq=%d, idx=%d)", seq, idx
            )

            if key not in _CHAINED_STORAGE:
                self.logger.debug(
                    "No chain found for %s (missing first frame)",
                    key,
                )
                return self.parsed

            # For VENTILAIRSEC continuation frames, payload starts at index 2
            # (bytes 2-3 are part of the payload, unlike in the first frame
            # where they encode the total length)
            cont_data = self.data[2:-5]
            _CHAINED_STORAGE[key]["data"].extend(cont_data)

            current_len = len(_CHAINED_STORAGE[key]["data"])
            expected_len = _CHAINED_STORAGE[key]["total_len"]

            self.logger.debug(
                "Chained progress (seq=%d, idx=%d): %d/%d bytes, new_chunk=%s",
                seq,
                idx,
                current_len,
                expected_len,
                bytes(cont_data).hex(),
            )

            self.parsed = OrderedDict()

            if current_len >= expected_len:
                complete_data = _CHAINED_STORAGE[key]["data"][:expected_len]

                # Reassemble as MSC packet: complete_data already contains RORG byte (0xD1)
                # Ventilairsec chained telegrams include the full MSC structure
                msc_data = complete_data + _CHAINED_STORAGE[key]["sender"] + [0]
                msc_packet = RadioPacket(
                    self.packet_type, msc_data, _CHAINED_STORAGE[key]["optional"]
                )

                del _CHAINED_STORAGE[key]
                msc_packet.parse()

                self.data = msc_packet.data
                self.optional = msc_packet.optional
                self.rorg = msc_packet.rorg
                self.rorg_func = msc_packet.rorg_func
                self.rorg_type = msc_packet.rorg_type
                self.rorg_manufacturer = msc_packet.rorg_manufacturer
                self.contains_eep = msc_packet.contains_eep
                self.learn = msc_packet.learn
                self.cmd = msc_packet.cmd
                self.parsed = msc_packet.parsed

                # Mark as reconstructed so downstream processing knows this was reassembled
                # Store reconstruction info that will help with later parsing attempts
                if not self.parsed:
                    # MSC packets don't auto-parse EEP (contains_eep=False)
                    # Mark as reconstructed so dongle can attempt profile-based parsing
                    self.parsed["reconstructed"] = {
                        "raw_value": True,
                        "rorg_manufacturer": self.rorg_manufacturer,
                        "cmd": self.cmd,
                    }

                self.logger.debug(
                    "Reconstructed MSC packet: rorg=0x%02X manufacturer=0x%03X cmd=%s parsed=%s",
                    self.rorg,
                    self.rorg_manufacturer if self.rorg_manufacturer else 0,
                    self.cmd,
                    bool(self.parsed),
                )

                return self.parsed

            return self.parsed

        if len(self.data) < 8:
            self.logger.error("Chained packet too short: %d bytes", len(self.data))
            return self.parsed

        # Extract sequence and index from byte 1
        # Bits 4-7: sequence number, Bits 0-3: index
        byte1 = self.data[1]
        seq = (byte1 >> 4) & 0x0F
        idx = byte1 & 0x0F

        # Total length from bytes 2-3 (only valid in first frame, idx=0)
        # In continuation frames, bytes 2-3 may contain other data
        total_len = (self.data[2] << 8) | self.data[3] if idx == 0 else 0

        # Create storage key
        sender_hex = enocean.utils.to_hex_string(self.sender).replace(":", "")
        chain_key = f"{sender_hex}.{seq}"

        self.logger.debug(
            "ChainedPacket.parse() - sender=%s, RORG=0x%02X, seq=%d, idx=%d, total_len=%d, data_len=%d",
            sender_hex,
            self.rorg,
            seq,
            idx,
            total_len,
            len(self.data),
        )

        if idx == 0:
            # First message of chain - store metadata
            self.logger.info(
                "Chained telegram: First message (seq=%d), total_length=%d bytes",
                seq,
                total_len,
            )

            # Extract first chunk of data (bytes 4 to -5, excluding sender and status)
            first_data = self.data[4:-5]

            _CHAINED_STORAGE[chain_key] = {
                "seq": seq,
                "total_len": total_len,
                "data": first_data,
                "sender": self.sender,
                "optional": self.optional,
            }

            # Mark as unparsed since this is an incomplete chain
            # Keep as OrderedDict (empty) to indicate incompleteness
            # The parsed OrderedDict is only populated when reassembly is complete
            self.parsed = OrderedDict()
            self.logger.debug(
                "ChainedPacket incomplete - not propagating to listeners (waiting for %d more bytes)",
                total_len - len(first_data),
            )
        else:
            # Continuation of chain
            self.logger.debug(
                "Chained telegram: Continuation (seq=%d, idx=%d)", seq, idx
            )

            if chain_key not in _CHAINED_STORAGE:
                self.logger.warning(
                    "Chained continuation without first message (chain_key=%s). Available keys: %s",
                    chain_key,
                    list(_CHAINED_STORAGE.keys()),
                )
                return self.parsed

            # Extract continuation data (bytes 2 to -5, including bytes 2-3 which are payload)
            cont_data = self.data[2:-5]

            _CHAINED_STORAGE[chain_key]["data"].extend(cont_data)

            current_len = len(_CHAINED_STORAGE[chain_key]["data"])
            expected_len = _CHAINED_STORAGE[chain_key]["total_len"]

            self.logger.debug(
                "Chained progress (seq=%d, idx=%d): %d/%d bytes, new_chunk=%s",
                seq,
                idx,
                current_len,
                expected_len,
                bytes(cont_data).hex(),
            )

            # Mark as unparsed - will only be parsed when complete
            # Keep as OrderedDict (empty) to indicate incompleteness
            self.parsed = OrderedDict()

            # Check if chain is complete
            if current_len >= expected_len:
                self.logger.debug(
                    "Chained telegram complete: Reassembling MSC packet from %d bytes",
                    expected_len,
                )

                # Get complete data and truncate to expected length
                complete_data = _CHAINED_STORAGE[chain_key]["data"][:expected_len]

                # Reassemble as MSC packet: [RORG] + complete_data + sender + status
                # RORG for MSC is 0xD1
                msc_data = (
                    [0xD1] + complete_data + _CHAINED_STORAGE[chain_key]["sender"] + [0]
                )

                # Create a complete MSC packet
                msc_packet = RadioPacket(
                    self.packet_type,
                    msc_data,
                    _CHAINED_STORAGE[chain_key]["optional"],
                )

                # Clean up storage
                del _CHAINED_STORAGE[chain_key]

                # Parse the MSC packet
                msc_packet.parse()

                # Copy the reassembled packet attributes to self
                self.data = msc_packet.data
                self.optional = msc_packet.optional
                self.rorg = msc_packet.rorg
                self.rorg_func = msc_packet.rorg_func
                self.rorg_type = msc_packet.rorg_type
                self.rorg_manufacturer = msc_packet.rorg_manufacturer
                self.contains_eep = msc_packet.contains_eep
                self.learn = msc_packet.learn
                self.cmd = msc_packet.cmd
                self.parsed = msc_packet.parsed

                # Mark as reconstructed so downstream processing knows this was reassembled
                # Store reconstruction info that will help with later parsing attempts
                if not self.parsed:
                    # MSC packets don't auto-parse EEP (contains_eep=False)
                    # Mark as reconstructed so dongle can attempt profile-based parsing
                    self.parsed["reconstructed"] = {
                        "raw_value": True,
                        "rorg_manufacturer": self.rorg_manufacturer,
                        "cmd": self.cmd,
                    }

                self.logger.info(
                    "MSC packet reconstructed successfully: RORG=0x%02X, FUNC=0x%02X, TYPE=0x%02X, Manufacturer=0x%03X",
                    self.rorg,
                    self.rorg_func if self.rorg_func is not None else 0,
                    self.rorg_type if self.rorg_type is not None else 0,
                    self.rorg_manufacturer if self.rorg_manufacturer is not None else 0,
                )

        return self.parsed
