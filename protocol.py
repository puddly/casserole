import re
import sys
import enum
import inspect
import asyncio
import logging
import itertools

import async_timeout
import serial_asyncio

from io import BytesIO
from collections import defaultdict

import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG')


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

        UNKNOWN = 0xFFFF

    def __init__(self, source, destination, data):
        self.source = source
        self.destination = destination
        self.data = data

    @classmethod
    def parse_commands(cls, data):
        f = BytesIO(data)

        command_type = int.from_bytes(f.read(1), 'big')

        if command_type != 0xF1:
            raise ValueError('Data is not a read/write command')

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

    def encode_data(self):
        if isinstance(self.data, (bytes, bytearray)):
            return self.data
            
        assert isinstance(self.data, list)

        result = b''
        result += b'\xF1'
        result += len(self.data).to_bytes(1, 'big')

        for command_id, endpoint_id, data in self.data:
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

        try:
            data = cls.parse_commands(payload)
        except ValueError:
            data = payload

        message = cls(source, destination, data)
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
        result += (1 + 1 + 1 + 1 + len(self.encode_data()) + 2 + 1).to_bytes(1, 'big')
        result += self.source.to_bytes(1, 'big')
        result += self.encode_data()

        return result

    def to_bytes(self, *, escape=True):
        result = self._dump_until_checksum()
        result += self.crc16(result).to_bytes(2, 'big')

        if escape:
            result = result[:1] + escape_bytes(result[1:], b'\xE0', b'\xE0\xE1\xE2\xE3')

        result += b'\xE3'
        result += b'\xE1'

        return result

    def __repr__(self):
        lines = [f'<{self.__class__.__name__}(source=0x{self.source:02X}, destination=0x{self.destination:02X}, data=[']

        if isinstance(self.data, list):
            for command_name, endpoint_id, data in self.data:
                lines.append(f'    ({command_name.name + ",":<13} 0x{endpoint_id:02X}, {data}),')
        else:
            lines.append(f'    {pretty_bytes(self.data)}')

        lines.append(']')

        return '\n'.join(lines)



class CasseroleMessage:
    class Commands(enum.Enum):
        BUS_MESSAGE = 0x01
        BUS_ERROR = 0x03

        SEND_BUS_MESSAGE = 0x11
        SEND_BUS_MESSAGE_ACK = 0x12
        SEND_BUS_MESSAGE_TX = 0x02

        PING = 0xFF
        HEARTBEAT = 0xFE
        DEBUG = 0xDE

    def __init__(self, type, payload):
        self.type = type
        self.payload = payload

    @property
    def size(self):
        return 2 + 1 + len(self.payload)

    def to_bytes(self):
        result = b''
        result += self.size.to_bytes(2, 'big')
        result += self.type.value.to_bytes(1, 'big')
        result += self.payload

        return result

    @classmethod
    def from_file(cls, f):
        size = int.from_bytes(read_exactly(f, 2), 'big')
        type = cls.Commands(int.from_bytes(read_exactly(f, 1), 'big'))
        payload = read_exactly(f, size)

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
        return f'<{self.__class__.__name__}(type={self.type}, payload={self.payload})'


class EventBus:
    def __init__(self):
        self.listeners = defaultdict(list)

    def on(self, key, callback=None):
        if callback is not None:
            self.listeners[key].append(callback)
            return

        def inner(function):
            self.listeners[key].append(function)
            return function

        return inner

    def emit(self, key, *args, **kwargs):
        for callback in self.listeners[key]:
            if inspect.iscoroutinefunction(callback):
                asyncio.create_task(callback(*args, **kwargs))
            else:
                callback(*args, **kwargs)

    def off(self, key, callback):
        self.listeners[key].remove(callback)


class CasseroleProtocol(asyncio.Protocol):
    def __init__(self):
        super().__init__()

        self.transport = None
        self.send_lock = asyncio.Lock()

        self.events = EventBus()
        self.received_messages = defaultdict(asyncio.Queue)

        self.incomplete_message = b''

        @self.events.on('packet:casserole')
        def casserole_handler(message):
            if message.type == CasseroleMessage.Commands.BUS_MESSAGE:
                self.events.emit('packet:ge', GEBusMessage.from_bytes(message.payload))
        
        @self.events.on('packet:ge')
        def ge_handler(message):
            pass

    async def send_casserole_message(self, message, accept=lambda m: True):
        async with self.send_lock:
            result_future = asyncio.get_event_loop().create_future()

            @self.events.on('packet:casserole')
            def on_packet(rx_message):
                if not accept(rx_message):
                    return

                result_future.set_result(rx_message)
                self.events.off('packet:casserole', on_packet)

            self.transport.write(message.to_bytes())
            logger.debug('>>> %s', message)

            try:
                return await result_future
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self.events.off('packet:casserole', on_packet)
                raise

    async def broadcast_ge_message(self, message):
        outer = CasseroleMessage(CasseroleMessage.Commands.SEND_BUS_MESSAGE, message.to_bytes(escape=True))
        results = asyncio.Queue()

        @self.events.on('packet:ge')
        def on_packet(rx_message):
            if message.destination != 0xFF and rx_message.source != message.destination:
                return

            if rx_message.destination != message.source:
                return

            # XXX: Expose the command properly
            if rx_message.data[0] != message.data[0]:
                return

            results.put_nowait(rx_message)

        await self.send_casserole_message(outer, accept=lambda m: m.type == CasseroleMessage.Commands.SEND_BUS_MESSAGE_TX)

        try:
            while True:
                yield await results.get()
        finally:
            self.events.off('packet:ge', on_packet)

    async def send_ge_message(self, message):
        async for response in self.broadcast_ge_message(message):
            return response

    async def ping(self):
        return await self.send_casserole_message(CasseroleMessage(CasseroleMessage.Commands.PING, b''), accept=lambda m: m.type == CasseroleMessage.Commands.PING)

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self.incomplete_message += data

        while True:
            if len(self.incomplete_message) < 3:
                return

            size = int.from_bytes(self.incomplete_message[0:2], 'big')
            packet_type = int.from_bytes(self.incomplete_message[2:3], 'big')

            if len(self.incomplete_message) < 2 + 1 + size:
                return

            message = self.incomplete_message[:2 + 1 + size]
            self.incomplete_message = self.incomplete_message[2 + 1 + size:]

            if CasseroleMessage.from_bytes(message).type != 0x01:
                logger.debug('<<< %s', CasseroleMessage.from_bytes(message))

            self.events.emit('packet:casserole', CasseroleMessage.from_bytes(message))

    def connection_lost(self, exc):
        pass


async def main(adapter):
    loop = asyncio.get_event_loop()
    transport, protocol = await serial_asyncio.create_serial_connection(loop, CasseroleProtocol, adapter, baudrate=19200)

    while not protocol.transport:
        logger.info('Waiting to connect...')
        await asyncio.sleep(1)

    async def ping():
        while True:
            try:
                with async_timeout.timeout(2):
                    logger.info('Waiting for a ping response...')
                    await protocol.ping()
                    break
            except asyncio.TimeoutError:
                print('Timed out!')

    # XXX some bug corrupts the first received message
    await ping()

    logger.info('Sending a broadcast to identify devices...')

    async for response in protocol.broadcast_ge_message(GEBusMessage(source=0x1B, destination=0xFF, data=b'\x01')):
        endpoint, version = response.source, response.data
        break

    logger.info('Found an appliance version %r at 0x%0.2X', version, endpoint)


    for i in range(1000):
        appliance = 0x23
        cycle = await protocol.send_ge_message(GEBusMessage(source=0x1B, destination=appliance, data=b'\xf0\x01\x20\x0A'))

        logger.info('Current selected cycle is %s', cycle.data)
        await asyncio.sleep(1)

if __name__ == '__main__':
    asyncio.run(main(sys.argv[1]))
