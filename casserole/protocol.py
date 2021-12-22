from __future__ import annotations

import enum

from verboselogs import VerboseLogger

from casserole.utils import pretty_bytes, read_exactly
from casserole.exceptions import ParsingError, IncompleteReadError

LOGGER = VerboseLogger(__name__)


class GEBusCommand(enum.IntEnum):
    READ = 0xF0
    WRITE = 0xF1
    SUBSCRIBE = 0xF2
    SUBSCRIBE_LIST = 0xF3
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


class GEBusPacket:
    """
    Encapsulated packet on the bus
    """

    ESCAPE_BYTE = 0xE0
    END_OF_FRAME2 = 0xE1
    START_OF_FRAME = 0xE2
    END_OF_FRAME = 0xE3

    def __init__(self, *, src: int, dst: int, command: int, payload: bytes, eof2: bool):
        self.src = src
        self.dst = dst
        self.command = command
        self.payload = payload
        self.eof2 = eof2

    @classmethod
    def deserialize(cls, data: bytes) -> tuple[GEBusPacket, bytes]:
        orig_data = data

        if data[0] != cls.START_OF_FRAME:
            raise ParsingError(f"Unexpected start of packet: 0x{data[0]:02X}", data[1:])

        data = data[1:]

        dst, data = cls.read_unescaped(data)
        size, data = cls.read_unescaped(data)

        if size < 7:
            raise ParsingError(f"Unexpected size: {size}", data)

        src, data = cls.read_unescaped(data)
        command, data = cls.read_unescaped(data)
        command = GEBusCommand(command)

        payload = bytearray()

        for i in range(size - 8):
            byte, data = cls.read_unescaped(data)
            payload.append(byte)

        checksum1, data = cls.read_unescaped(data)
        checksum2, data = cls.read_unescaped(data)
        checksum = int.from_bytes(bytes([checksum1, checksum2]), "big")

        end_of_frame, data = cls.read_unescaped(data)

        if end_of_frame != cls.END_OF_FRAME:
            raise ParsingError(f"Unexpected end of frame: {end_of_frame:02X}", data)

        end_of_frame2, data = cls.read_unescaped(data)

        if end_of_frame2 != cls.END_OF_FRAME2:
            data = bytes([end_of_frame2]) + data
            eof2 = False
        else:
            eof2 = True

        message = cls(src=src, dst=dst, command=command, payload=payload, eof2=eof2)
        reconstructed = message.serialize()

        if reconstructed != orig_data[: len(reconstructed)]:
            raise ParsingError(
                f"Reconstructed packet and original differ:"
                f" {reconstructed} != {orig_data[:len(reconstructed)]}",
                data,
            )

        if message.checksum != checksum:
            raise ParsingError(
                f"Expected checksum {checksum:02X}, got {message.checksum:02X}", data
            )

        return message, data

    @classmethod
    def read_unescaped(cls, data: bytes) -> tuple[int, bytes]:
        if not data:
            raise IncompleteReadError()

        if data[0] != cls.ESCAPE_BYTE:
            return data[0], data[1:]

        if len(data) < 2:
            raise IncompleteReadError()
        elif not 0xE0 <= data[1] <= 0xE3:
            raise ParsingError(
                f"Invalid escape sequence: {cls.ESCAPE_BYTE:02X} {data[0]:02X}", data
            )

        return data[1], data[2:]

    @classmethod
    def unescape(cls, data: bytes) -> tuple[bytes, bytes]:
        result = bytearray()
        unescaping = False

        for c in data:
            if c == cls.ESCAPE_BYTE:
                unescaping = True
                continue

            if unescaping and not 0xE0 <= c <= 0xE3:
                return result, data

            result.append(c)

        if unescaping:
            return result, bytes([cls.ESCAPE_BYTE]) + data

        return result

    @classmethod
    def escape(cls, data: bytes) -> bytes:
        result = bytearray()

        for c in data:
            if 0xE0 <= c <= 0xE3:
                result.append(cls.ESCAPE_BYTE)

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

    @property
    def checksum(self) -> int:
        return self.crc16(self.serialize(stop_at_checksum=True))

    def serialize(self, *, stop_at_checksum=False) -> bytes:
        if not isinstance(self.payload, (bytes, bytearray)):
            payload = self.payload.serialize()
        else:
            payload = self.payload

        header = bytes([self.START_OF_FRAME])
        body = (
            bytes(
                [
                    self.dst,
                    (1 + 1 + 1 + 1 + 1 + len(payload) + 2 + 1),
                    self.src,
                    self.command,
                ]
            )
            + payload
        )

        if stop_at_checksum:
            return header + body

        body += self.checksum.to_bytes(2, "big")

        escaped_body = self.escape(body)
        escaped_body += bytes([self.END_OF_FRAME])

        if self.eof2:
            escaped_body += bytes([self.END_OF_FRAME2])

        return header + escaped_body

    def __repr__(self) -> str:
        output = [
            f"<{self.__class__.__name__}(src=0x{self.src:02X}, dst=0x{self.dst:02X},",
            f" command={self.command!r}, data=",
        ]

        if isinstance(self.payload, (bytes, bytearray)):
            output.append(f"{pretty_bytes(self.payload)}")
        else:
            output.append(f"{self.payload}")

        output.append(f", eof2={self.eof2}>")

        return "".join(output)


class GEBusMessageCommands:
    def __init__(self, commands):
        self.commands = commands

    @classmethod
    def from_file(cls, f):
        count = int.from_bytes(read_exactly(f, 1), "big")
        commands = []

        next_byte = None

        for i in range(count):
            if next_byte is not None:
                subcommand_byte = next_byte
                next_byte = None
            else:
                subcommand_byte = read_exactly(f, 1)

            subcommand = cls.Commands(int.from_bytes(subcommand_byte, "big"))
            endpoint_id = int.from_bytes(read_exactly(f, 1), "big")

            # It's OK not to read anything here
            next_byte = f.read(1)

            if not next_byte or any(
                next_byte[0] == m.value for m in cls.Commands.__members__.values()
            ):
                commands.append((subcommand, endpoint_id, None))
                continue

            size = int.from_bytes(next_byte, "big")
            next_byte = None

            data = read_exactly(f, size)

            commands.append((subcommand, endpoint_id, data))

        return cls(commands)

    def to_bytes(self):
        result = b""
        result += len(self.commands).to_bytes(1, "big")

        for command, endpoint_id, data in self.commands:
            result += command.value.to_bytes(1, "big")
            result += endpoint_id.to_bytes(1, "big")

            if data is not None:
                result += len(data).to_bytes(1, "big")
                result += data

        return result

    def __repr__(self):
        lines = [f"<{self.__class__.__name__}(commands=["]

        for command, endpoint_id, data in self.commands:
            if (data is not None and command == self.Commands.READ) or (
                data is None and command != self.Commands.READ
            ):
                command_name = f"{command.name}_RESP"
            else:
                command_name = command.name

            if data is not None:
                lines.append(
                    f"    {command_name:>14}(endpoint=0x{endpoint_id:02X},"
                    f" data=[{pretty_bytes(data)}])"
                )
            else:
                lines.append(f"    {command_name:>14}(endpoint=0x{endpoint_id:02X})")

        lines.append("]>")

        return "\n".join(lines)
