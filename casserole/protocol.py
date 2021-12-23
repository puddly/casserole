from __future__ import annotations

import enum

from verboselogs import VerboseLogger

from casserole.utils import pretty_bytes
from casserole.exceptions import ParsingError, IncompleteReadError

LOGGER = VerboseLogger(__name__)


class GEAFrame:
    """
    Encapsulated frame on the bus
    """

    ESCAPE = 0xE0
    ACK = 0xE1
    START_OF_FRAME = 0xE2
    END_OF_FRAME = 0xE3

    def __init__(self, *, dst: int, src: int, payload: bytes, ack: bool):
        self.dst = dst
        self.src = src
        self.payload = payload
        self.ack = ack

    @classmethod
    def deserialize(cls, data: bytes) -> tuple[GEAFrame, bytes]:
        orig_data = data

        if data[0] != cls.START_OF_FRAME:
            raise ParsingError(f"Unexpected start of frame: 0x{data[0]:02X}", data[1:])

        data = data[1:]

        dst, data = cls.read_unescaped(data)
        size, data = cls.read_unescaped(data)

        if size < 7:
            raise ParsingError(f"Unexpected size: {size}", data)

        src, data = cls.read_unescaped(data)

        payload = bytearray()

        for i in range(size - 7):
            byte, data = cls.read_unescaped(data)
            payload.append(byte)

        checksum1, data = cls.read_unescaped(data)
        checksum2, data = cls.read_unescaped(data)
        checksum = int.from_bytes(bytes([checksum1, checksum2]), "big")

        end_of_frame, data = cls.read_unescaped(data)

        if end_of_frame != cls.END_OF_FRAME:
            raise ParsingError(f"Unexpected end of frame: {end_of_frame:02X}", data)

        ACK, data = cls.read_unescaped(data)

        if ACK != cls.ACK:
            data = bytes([ACK]) + data
            ack = False
        else:
            ack = True

        message = cls(dst=dst, src=src, payload=payload, ack=ack)
        reconstructed = message.serialize()

        if reconstructed != orig_data[: len(reconstructed)]:
            raise ParsingError(
                f"Reconstructed frame and original differ:"
                f" {reconstructed} != {orig_data[:len(reconstructed)]}",
                data,
            )

        if message.compute_checksum() != checksum:
            raise ParsingError(
                f"Expected checksum {checksum:02X}, got {message.checksum:02X}", data
            )

        return message, data

    @classmethod
    def read_unescaped(cls, data: bytes) -> tuple[int, bytes]:
        if not data:
            raise IncompleteReadError()

        if data[0] != cls.ESCAPE:
            return data[0], data[1:]

        if len(data) < 2:
            raise IncompleteReadError()
        elif not 0xE0 <= data[1] <= 0xE3:
            raise ParsingError(
                f"Invalid escape sequence: {cls.ESCAPE:02X} {data[0]:02X}", data
            )

        return data[1], data[2:]

    @classmethod
    def unescape(cls, data: bytes) -> tuple[bytes, bytes]:
        result = bytearray()
        unescaping = False

        for c in data:
            if c == cls.ESCAPE:
                unescaping = True
                continue

            if unescaping and not 0xE0 <= c <= 0xE3:
                return result, data

            result.append(c)

        if unescaping:
            return result, bytes([cls.ESCAPE]) + data

        return result

    @classmethod
    def escape(cls, data: bytes) -> bytes:
        result = bytearray()

        for c in data:
            if 0xE0 <= c <= 0xE3:
                result.append(cls.ESCAPE)

            result.append(c)

        return result

    @staticmethod
    def crc16(data: bytes) -> int:
        """
        CRC parameters found with http://reveng.sourceforge.net/:
            width=16  poly=0x1021  init=0xe300  refin=false  refout=false  xorout=0x0000
            check=0x5b10  residue=0x0000  name=(none)
        """

        crc = 0xE300

        for b in data:
            crc ^= b << 8

            for j in range(0, 8):
                if crc & 0b1000000000000000:
                    crc <<= 1
                    crc ^= 0x1021
                else:
                    crc <<= 1

                crc &= 0xFFFF

        return crc

    def compute_checksum(self) -> int:
        return self.crc16(self.serialize(stop_at_checksum=True))

    def serialize(self, *, stop_at_checksum=False) -> bytes:
        if not isinstance(self.payload, (bytes, bytearray)):
            payload = self.payload.serialize()
        else:
            payload = self.payload

        size = 1 + 1 + 1 + 1 + len(payload) + 2 + 1

        if self.ack:
            size += 0

        header = bytes([self.START_OF_FRAME])
        body = bytes([self.dst, size, self.src]) + payload

        if stop_at_checksum:
            return header + body

        body += self.compute_checksum().to_bytes(2, "big")

        escaped_body = self.escape(body)
        escaped_body += bytes([self.END_OF_FRAME])

        if self.ack:
            escaped_body += bytes([self.ACK])

        return header + escaped_body

    def __repr__(self) -> str:
        output = [
            f"<{self.__class__.__name__}(src=0x{self.src:02X}, dst=0x{self.dst:02X},",
            " payload=",
        ]

        if isinstance(self.payload, (bytes, bytearray)):
            output.append(f"{pretty_bytes(self.payload)}")
        else:
            output.append(f"{self.payload}")

        output.append(f", ack={self.ack}>")

        return "".join(output)


class ERDCommandID(enum.IntEnum):
    READ = 0xF0
    WRITE = 0xF1
    SUBSCRIBE = 0xF2
    LIST_SUBSCRIBED = 0xF3
    UNSUBSCRIBE = 0xF4
    PUBLISH = 0xF5

    @classmethod
    def _missing_(cls, value):
        new = int.__new__(cls, value)
        new._name_ = f"unknown_0x{value:02X}"
        new._value_ = value

        return new

    def __repr__(self):
        return f"<{self.__class__.__name__}.{self.name}: 0x{self.value:02X}>"


class ERDCommand:
    def __init__(self, command: ERDCommandID, erds: list[tuple[int, bytes]]):
        self.command = command
        self.erds = erds

    @classmethod
    def deserialize(cls, data: bytes) -> tuple[ERDCommand, bytes]:
        if len(data) < 2:
            raise ParsingError("Data is too short", data)

        command = ERDCommandID(data[0])
        count = data[1]
        data = data[2:]

        erds = []

        for i in range(count):
            erd_msb = data[0]
            erd_lsb = data[1]
            erd = (erd_msb << 8) | (erd_lsb << 0)

            if len(data) == 2:
                erds.append((erd, None))
                data = data[2:]
                continue

            size = data[2]
            payload = bytes(data[3 : 3 + size])
            data = data[3 + size :]

            erds.append((erd, payload))

        return cls(command=command, erds=erds), data

    def serialize(self) -> bytes:
        result = bytes([self.command, len(self.erds)])

        for erd, payload in self.erds:
            if payload is not None:
                result += erd.to_bytes(2, "big") + bytes([len(payload)]) + payload
            else:
                result += erd.to_bytes(2, "big")

        return result

    def __repr__(self) -> str:
        erds = ", ".join(
            [f"0x{erd:04X}:{pretty_bytes(payload)}" for erd, payload in self.erds]
        )
        return f"<{self.__class__.__name__}(command={self.command!r}, erds=[{erds}])>"


if __name__ == "__main__":
    payload = bytes.fromhex("F0 01 20 12")
    grp, rest = ERDCommand.deserialize(payload)

    print(grp)
    print(rest)
