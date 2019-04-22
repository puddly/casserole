import re
import sys
import enum
import asyncio
import itertools

import serial_asyncio

from io import BytesIO
from collections import defaultdict


def escape_bytes(data, escape_char, bad_chars):
    return re.sub(rb'([' + re.escape(bad_chars) + rb'])', re.escape(escape_char) + rb'\1', data)

def unescape_bytes(data, escape_char, bad_chars):
    return re.sub(re.escape(escape_char) + rb'([' + re.escape(bad_chars) + rb'])', rb'\1', data)


def read_exactly(f, size):
    result = b''

    while len(result) < size:
        chunk = f.read(size - len(result))

        if not chunk and len(result) != size:
            raise ValueError(f'Could only read {len(result)} of {size} bytes!')

        result += chunk

    return result


def peek(f, n):
    old = f.tell()
    result = f.read(n)
    f.seek(old)

    return result


def pretty_bytes(bytes_object):
    return ' '.join([hex(b)[2:].zfill(2) for b in bytes_object])


class GEBusMessage:
    class Commands(enum.Enum):
        READ = 0xF0
        WRITE = 0xF1
        SUBSCRIBE = 0xF2
        SUBSCRIBE_LIST = 0xF3
        UNSUBSCRIBE = 0xF4
        PUBLISH = 0xF5

    def __init__(self, source, destination, commands):
        self.source = source
        self.destination = destination
        self.commands = commands

    @classmethod
    def parse_commands(cls, data):
        f = BytesIO(data)

        command_type = int.from_bytes(f.read(1), 'big')
        assert command_type == 0xf1  # I have yet to see any other type

        # Not sure why this is necessary
        count = int.from_bytes(f.read(1), 'big')

        commands = []

        for i in range(count):
            subcommand = cls.Commands(int.from_bytes(f.read(1), 'big'))
            endpoint_id = int.from_bytes(f.read(1), 'big')

            next_byte = peek(f, 1)

            if not next_byte or next_byte in bytearray([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5]):
                commands.append((subcommand, endpoint_id, None))
                continue

            command_data_size = int.from_bytes(f.read(1), 'big')
            command_data = read_exactly(f, command_data_size)

            assert command_data_size > 0

            commands.append((subcommand, endpoint_id, command_data))

        remaining = f.read()

        if remaining:
            raise ValueError(f'Unparsed data remains at the end: {remaining}')

        return commands

    def pack_commands(self):
        result = b''
        result += b'\xF1'
        result += len(self.commands).to_bytes(1, 'big')

        for command_id, endpoint_id, data in self.commands:
            result += command_id.value.to_bytes(1, 'big')
            result += endpoint_id.to_bytes(1, 'big')

            if data is not None:
                result += len(data).to_bytes(1, 'big')
                result += data

        return result

    @classmethod
    def from_file(cls, f):
        assert read_exactly(f, 1) == b'\xE2'

        destination = int.from_bytes(read_exactly(f, 1), 'big')

        size = int.from_bytes(read_exactly(f, 1), 'big')
        assert size >= 7

        source = int.from_bytes(read_exactly(f, 1), 'big')
        payload = read_exactly(f, size - 7)

        checksum = int.from_bytes(read_exactly(f, 2), 'big')

        assert read_exactly(f, 1) == b'\xE3'

        message = cls(source, destination, cls.parse_commands(payload))
        assert message.checksum == checksum

        return message

    @classmethod
    def from_bytes(cls, data):
        f = BytesIO(data)
        message = cls.from_file(f)
        remaining = f.read()

        if remaining:
            raise ValueError(f'Unused data remains at the end: {remaining}')

        return message

    @staticmethod
    def crc16(data):
        '''
        CRC parameters found with http://reveng.sourceforge.net/:
            width=16  poly=0x1021  init=0xe300  refin=false  refout=false  xorout=0x0000  check=0x5b10  residue=0x0000  name=(none)
        '''

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
    def checksum(self):
        return self.crc16(self._dump_until_checksum())

    def _dump_until_checksum(self):
        result = b''
        result += b'\xE2'
        result += self.destination.to_bytes(1, 'big')
        result += (1 + 1 + 1 + 1 + len(self.pack_commands()) + 2 + 1).to_bytes(1, 'big')
        result += self.source.to_bytes(1, 'big')
        result += self.pack_commands()

        return result

    def to_bytes(self, *, escape=False):
        result = self._dump_until_checksum()
        result += self.crc16(result).to_bytes(2, 'big')

        if escape:
            result = result[:1] + escape_bytes(result[1:], b'\xE0', b'\xE0\xE1\xE2\xE3')

        result += b'\xE3'
        result += b'\xE1'

        return result

    def __repr__(self):
        lines = [f'<{self.__class__.__name__}(source=0x{self.source:02X}, destination=0x{self.destination:02X}, commands=[']

        for command_name, endpoint_id, data in self.commands:
            lines.append(f'    ({command_name.name + ",":<13} 0x{endpoint_id:02X}, {data}),')

        lines.append(']')

        return '\n'.join(lines)


class CasseroleMessage:
    SERVER_RX_BUS_MESSAGE_ID = 0x01
    SERVER_TX_SERIAL_ID = 0x02
    SERVER_RX_BUS_ERROR_ID = 0x03

    CLIENT_SEND_BUS_MESSAGE_ID = 0x11

    def __init__(self, type, payload):
        self.type = type
        self.payload = payload

    @property
    def size(self):
        return 2 + 1 + len(self.payload)

    def to_bytes(self):
        result = b''
        result += self.size.to_bytes(2, 'big')
        result += self.type.to_bytes(1, 'big')
        result += self.payload

        return result

    @classmethod
    def from_file(cls, f):
        size = int.from_bytes(read_exactly(f, 2), 'big')
        type = int.from_bytes(read_exactly(f, 1), 'big')
        payload = read_exactly(f, size)

        assert type in (0x01, 0x02, 0x03, 0x11)

        return cls(type, payload)

    @classmethod
    def from_bytes(cls, data):
        f = BytesIO(data)
        message = cls.from_file(f)
        remaining = f.read()

        if remaining:
            raise ValueError(f'Unused data remains at the end: {remaining}')

        return message

    def __repr__(self):
        return f'<{self.__class__.__name__}(type=0x{self.type:02X}, payload={self.payload})'


class CasseroleProtocol(asyncio.Protocol):
    def __init__(self):
        super().__init__()

        self.send_lock = asyncio.Lock()
        self.received_messages = defaultdict(asyncio.Queue)

        self.incomplete_message = b''

    async def send(self, message):
        # We can send only one message at a time for now
        async with self.send_lock:
            outer_message = CasseroleMessage(CasseroleMessage.CLIENT_SEND_BUS_MESSAGE_ID, message.to_bytes(escape=True))
            self.transport.write(outer_message)

            await self.received_messages[CasseroleMessage.SERVER_TX_SERIAL_ID].get()

    async def receive(self):
        # We receive either a message or an error
        rx_task = asyncio.create_task(self.received_messages[CasseroleMessage.SERVER_RX_BUS_MESSAGE_ID].get())
        err_task = asyncio.create_task(self.received_messages[CasseroleMessage.SERVER_RX_BUS_ERROR_ID].get())

        done, pending = await asyncio.wait([rx_task, err_task], return_when=asyncio.FIRST_COMPLETED)

        assert len(done) == 1 and len(pending) == 1

        # Make sure to cancel the task so the queue isn't consumed after we exit
        for task in pending:
            task.cancel()

        return await list(done)[0]


    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self.incomplete_message += data

        if len(self.incomplete_message) < 3:
            return

        size = int.from_bytes(self.incomplete_message[0:2], 'big')
        packet_type = int.from_bytes(self.incomplete_message[2:3], 'big')

        if len(self.incomplete_message) < 2 + 1 + size:
            return

        message = self.incomplete_message[:2 + 1 + size]
        self.incomplete_message = self.incomplete_message[2 + 1 + size:]

        self.received_messages[packet_type].put_nowait(CasseroleMessage.from_bytes(message))

    def connection_lost(self, exc):
        pass


async def main(adapter):
    loop = asyncio.get_event_loop()
    transport, protocol = await serial_asyncio.create_serial_connection(loop, CasseroleProtocol, adapter, baudrate=115200)

    # Visually distinguish groups of commands
    last_pair = None

    while True:
        message = await protocol.receive()

        if message.type == CasseroleMessage.SERVER_RX_BUS_ERROR_ID:
            print(f'Received an error: {message.payload}')
        elif message.type == CasseroleMessage.SERVER_RX_BUS_MESSAGE_ID:
            ge_message = GEBusMessage.from_bytes(message.payload)

            pair = (ge_message.source, ge_message.destination)

            if pair != last_pair:
                last_pair = pair
                print()

            print(f'               {pretty_bytes(message.payload)}')

            for command, endpoint, data in ge_message.commands:
                '''
                if ge_message.source == 0x23 and endpoint == 0x2E:
                    # Cycle knob state

                    turn_count = data[1]
                    history = data[3:-1]

                    named_history = [{
                        0x01: 'Start (pressed)',
                        0x02: 'Start (released)',

                        0x03: 'Deep Rinse (pressed)',
                        0x04: 'Deep Rinse (released)',

                        0x05: 'Cycles (Off)',
                        0x06: 'Cycles (Drain & Spin)',
                        0x07: 'Cycles (Speed Wash)',
                        0x08: 'Cycles (Delicates)',
                        0x09: 'Cycles (Casuals)',
                        0x0a: 'Cycles (Bulky Items)',

                        0x0b: 'Cycles (Whites, Heavy)',
                        0x0c: 'Cycles (Whites, Medium)',
                        0x0d: 'Cycles (Whites, Light)',

                        0x0e: 'Cycles (Colors, Heavy)',
                        0x0f: 'Cycles (Colors, Medium)',
                        0x10: 'Cycles (Colors, Light)',

                        0x11: 'Temperature (Tap Cold)',
                        0x12: 'Temperature (Hot)',
                        0x13: 'Temperature (Warm)',
                        0x14: 'Temperature (Colors)',
                        0x15: 'Temperature (Cool)',
                        0x16: 'Temperature (Cold)',

                        0x17: 'Options (Off)',
                        0x18: 'Options (2nd Rinse)',
                        0x19: 'Options (Pre-Soak + 2nd Rinse)',
                        0x1a: 'Options (unpopulated)',
                        0x1b: 'Options (Pre-Soak 15 min)',
                    }[h] for h in history]

                    print()
                    print(f'0x{ge_message.source:02X} --> 0x{ge_message.destination:02X}  {command.name:<17}[0x{endpoint:02X}]  {pretty_bytes(data)}')

                    for h in named_history:
                        print(f'    {h}')
                '''

                command_name = None

                # Naming is inverted for READs, as expected
                if command == GEBusMessage.Commands.READ:
                    command_name = 'READ_RESP' if data is not None else 'READ'
                elif data is None:
                    command_name = command.name + '_RESP'
                else:
                    command_name = command.name

                print(f'0x{ge_message.source:02X} --> 0x{ge_message.destination:02X}  {command_name:<17}[0x{endpoint:02X}]  {pretty_bytes(data) if data else ""}')

                assert ge_message.source == 0x23 and ge_message.destination == 0x2D or ge_message.source == 0x2D and ge_message.destination == 0x23

    #await protocol.send(GEBusMessage(source=0x1B, destination=0x01, commands=[]))



if __name__ == '__main__':
    asyncio.run(main(sys.argv[1]))
