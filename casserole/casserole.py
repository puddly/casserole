import sys
import enum
import asyncio
import inspect
from io import BytesIO
from collections import defaultdict

import coloredlogs
import async_timeout
import serial_asyncio
from verboselogs import VerboseLogger
from gea.protocol import GEBusPacket, GEBusMessageCommands, pretty_bytes, read_exactly

LOGGER = VerboseLogger(__name__)


class CasseroleError(ValueError):
    pass


class TinyCOBS:
    @staticmethod
    def encode(data):
        assert len(data) <= 0xFF - 2
        data = bytes(data) + b"\x00"

        index_of_last_zero = 0
        result = bytearray([0x00] * (1 + len(data)))

        for offset in range(len(data)):
            byte = data[offset]

            if byte == 0x00:
                result[index_of_last_zero] = offset - index_of_last_zero + 1
                index_of_last_zero = offset + 1
            else:
                result[offset + 1] = byte

        return result

    @staticmethod
    def decode(data):
        assert 2 <= len(data) <= 0xFF

        output = bytearray([0x00] * (len(data) - 1))
        next_zero_in = data[0]

        for offset in range(len(data) - 1):
            next_zero_in -= 1
            byte = data[offset + 1]

            if next_zero_in == 0:
                output[offset] = 0x00
                next_zero_in = byte

                if offset + next_zero_in > len(data):
                    raise ValueError("Invalid zero pointer")
            else:
                output[offset] = byte

        return output[:-1]


class CasseroleMessage:
    class Commands(enum.Enum):
        BUS_MESSAGE = 0x01
        BUS_ERROR = 0x03

        SEND_BUS_MESSAGE = 0x11
        SEND_BUS_MESSAGE_ACK = 0x12
        SEND_BUS_MESSAGE_ERR = 0x13
        SEND_BUS_MESSAGE_TX = 0x02

        PING = 0xFF
        HEARTBEAT = 0xFE
        DEBUG = 0xDE

    def __init__(self, type, payload):
        self.type = type
        self.payload = payload

    @property
    def size(self):
        return 1 + 1 + len(self.payload) + 2

    def to_bytes(self):
        result = b""
        result += self.size.to_bytes(1, "big")
        result += self.type.value.to_bytes(1, "big")
        result += self.payload
        result += GEBusPacket.crc16(result).to_bytes(2, "big")

        assert GEBusPacket.crc16(result) == 0x0000

        return result

    @classmethod
    def from_file(cls, f):
        size = int.from_bytes(read_exactly(f, 2), "big")
        type = cls.Commands(int.from_bytes(read_exactly(f, 1), "big"))
        payload = read_exactly(f, size)

        return cls(type, payload)

    @classmethod
    def from_bytes(cls, data):
        f = BytesIO(data)
        message = cls.from_file(f)
        remaining = f.read()

        if remaining:
            raise ValueError(f"Unused data remains at the end: {remaining}")

        return message

    def __repr__(self):
        return f"<{self.__class__.__name__}(type={self.type}, payload={self.payload})"


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
        if callback in self.listeners[key]:
            self.listeners[key].remove(callback)


class CasseroleProtocol(asyncio.Protocol):
    def __init__(self):
        super().__init__()

        self.transport = None
        self.send_lock = asyncio.Lock()

        self.events = EventBus()
        self.received_messages = defaultdict(asyncio.Queue)

        self._buffer = b""
        self._wait_for_resync = False

        @self.events.on("packet:casserole")
        def casserole_handler(message):
            if message.type == CasseroleMessage.Commands.BUS_MESSAGE:
                packet, remaining = GEBusPacket.from_bytes(message.payload)
                assert not remaining

                self.events.emit("packet:ge", packet)
            elif message.type == CasseroleMessage.Commands.SEND_BUS_MESSAGE_ERR:
                LOGGER.error("Caught an error: %s", message.payload)

        states = defaultdict(lambda: defaultdict(bytes))

        @self.events.on("packet:ge")
        def ge_handler(message):
            if message.command != 0xF1:
                LOGGER.warning("Unknown command type: %x", message.command)
                return

            KNOBS = 0x2D
            BOARD = 0x23

            if message.source in (KNOBS, BOARD) and message.destination in (
                BOARD,
                KNOBS,
            ):
                commands = GEBusMessageCommands.from_bytes(message.data)

                important = message.destination == 0x23 and any(
                    ep == 0x2E for _, ep, _ in commands.commands
                )

                for command, endpoint_id, data in commands.commands:
                    if (
                        command == GEBusMessageCommands.Commands.WRITE
                        and data is not None
                    ):
                        # This is some kind of rolling counter
                        if endpoint_id == 0x33:
                            continue

                        current_value = states[message.destination][endpoint_id]

                        if not important and current_value == data:
                            continue

                        if important or not (
                            message.source == 0x23
                            and message.destination == 0x2D
                            and endpoint_id == 0x19
                        ):
                            LOGGER.debug(
                                "%x wrote to %x endpoint %x=[%s]",
                                message.source,
                                message.destination,
                                endpoint_id,
                                pretty_bytes(data),
                            )

                        states[message.destination][endpoint_id] = data
                    elif (
                        command == GEBusMessageCommands.Commands.READ
                        and data is not None
                    ):
                        current_value = states[message.source][endpoint_id]

                        if not important and current_value == data:
                            continue

                        LOGGER.debug(
                            "%x read from %x ep %x unexpected value %s",
                            message.source,
                            message.destination,
                            endpoint_id,
                            pretty_bytes(data),
                        )
                        states[message.source][endpoint_id] = data

    async def send_casserole_message(self, message, accept=lambda m: True):
        async with self.send_lock:
            result_future = asyncio.get_event_loop().create_future()

            try:

                @self.events.on("packet:casserole")
                def on_packet(rx_message):
                    if not accept(rx_message):
                        return

                    result_future.set_result(rx_message)
                    self.events.off("packet:casserole", on_packet)

                # We handle framing transparently
                LOGGER.spam(">>> %s", message)
                self.transport.write(TinyCOBS.encode(message.to_bytes()))

                return await result_future
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self.events.off("packet:casserole", on_packet)
                raise

    async def broadcast_ge_message(self, message, *, retry=5, timeout=2):
        for i in range(retry):
            try:
                iterator = self._broadcast_ge_message(message)

                while True:
                    async with async_timeout.timeout(timeout):
                        try:
                            yield await iterator.__anext__()
                        except StopAsyncIteration:
                            return
            except (CasseroleError, asyncio.TimeoutError):
                LOGGER.error("Failed to send message. Retrying...")

        raise CasseroleError("Could not send the message")

    async def _broadcast_ge_message(self, message):
        outer = CasseroleMessage(
            CasseroleMessage.Commands.SEND_BUS_MESSAGE, message.to_bytes()
        )
        results = asyncio.Queue()

        @self.events.on("packet:ge")
        def on_packet(rx_message):
            if message.destination != 0xFF and rx_message.source != message.destination:
                return

            if rx_message.destination != message.source:
                return

            if rx_message.command != message.command:
                return

            results.put_nowait(rx_message)

        try:
            await self.send_casserole_message(
                outer,
                accept=lambda m: m.type
                in [
                    CasseroleMessage.Commands.SEND_BUS_MESSAGE_TX,
                    CasseroleMessage.Commands.SEND_BUS_MESSAGE_ACK,
                    CasseroleMessage.Commands.SEND_BUS_MESSAGE_ERR,
                ],
            )

            while True:
                yield await results.get()
        finally:
            self.events.off("packet:ge", on_packet)

    async def send_ge_message(self, message, *, retry=5, timeout=2):
        async for response in self.broadcast_ge_message(
            message, retry=retry, timeout=timeout
        ):
            return response

    async def ping(self):
        return await self.send_casserole_message(
            CasseroleMessage(CasseroleMessage.Commands.PING, b""),
            accept=lambda m: m.type == CasseroleMessage.Commands.PING,
        )

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        if self._wait_for_resync:
            if b"\x00" not in data:
                return

            # COBS ensures null bytes exist only at frame boundaries
            self._wait_for_resync = False
            self._buffer = data[data.index(b"\x00") + 1 :]

        self._buffer += data

        while b"\x00" in self._buffer:
            frame, _, self._buffer = self._buffer.partition(b"\x00")
            frame += b"\x00"

            try:
                packet = TinyCOBS.decode(frame)
            except ValueError:
                LOGGER.error("Invalid frame! Resyncing...")
                self._buffer = b""
                self._wait_for_resync = True
                return

            try:
                parsed_message = CasseroleMessage.from_bytes(packet)
            except ValueError:
                LOGGER.error("Caught an error while reading packet! Discarding...")
                continue

            LOGGER.spam("<<< %s", parsed_message)

            self.events.emit("packet:casserole", parsed_message)

    def connection_lost(self, exc):
        pass


class StackedWasherControls:
    class Endpoints(enum.Enum):
        LIGHT_ON = 0x11
        LIGHT_WASH = 0x12
        LIGHT_RINSE = 0x13
        LIGHT_SPIN = 0x14
        LIGHT_LID_LOCKED = 0x15

    class Events(enum.Enum):
        BUTTON_START_PRESSED = 0x01
        BUTTON_START_RELEASED = 0x02

        BUTTON_DEEP_RINSE_PRESSED = 0x03
        BUTTON_DEEP_RINSE_RELEASED = 0x04

        KNOB_CYCLES_OFF = 0x05
        KNOB_CYCLES_DRAIN_AND_SPIN = 0x06
        KNOB_CYCLES_SPEED_WASH = 0x07
        KNOB_CYCLES_DELICATES = 0x08
        KNOB_CYCLES_CASUALS = 0x09
        KNOB_CYCLES_BULKY_ITEMS = 0x0A

        KNOB_CYCLES_WHITES_HEAVY = 0x0B
        KNOB_CYCLES_WHITES_MEDIUM = 0x0C
        KNOB_CYCLES_WHITES_LIGHT = 0x0D

        KNOB_CYCLES_COLORS_HEAVY = 0x0E
        KNOB_CYCLES_COLORS_MEDIUM = 0x0F
        KNOB_CYCLES_COLORS_LIGHT = 0x10

        KNOB_TEMPERATURE_TAP_COLD = 0x11
        KNOB_TEMPERATURE_HOT = 0x12
        KNOB_TEMPERATURE_WARM = 0x13
        KNOB_TEMPERATURE_COLORS = 0x14
        KNOB_TEMPERATURE_COOL = 0x15
        KNOB_TEMPERATURE_COLD = 0x16

        KNOB_OPTIONS_OFF = 0x17
        KNOB_OPTIONS_2ND_RINSE = 0x18
        KNOB_OPTIONS_PRE_SOAK_AND_2ND_RINSE = 0x19
        KNOB_OPTIONS_UNPOPULATED = 0x1A
        KNOB_OPTIONS_PRE_SOAK_15_MIN = 0x1B


async def attempt_washer_remote_start(protocol):
    loop = asyncio.get_event_loop()

    # Capture a packet from the knobs board to steal its counter
    LOGGER.info("Waiting for packet from knobs board...")
    sample_commands_future = loop.create_future()

    # XXX: wrap this in a function
    @protocol.events.on("packet:ge")
    def on_packet(m):
        if not (m.destination == 0x23 and m.source == 0x2D and m.command == 0xF1):
            return

        commands = GEBusMessageCommands.from_bytes(m.data).commands

        # We need both a knobs state write and a "packet id" write
        try:
            knobs_state_data = next(
                data
                for command, endpoint, data in commands
                if command == GEBusMessageCommands.Commands.WRITE and endpoint == 0x2E
            )
            unknown = next(
                data
                for command, endpoint, data in commands
                if command == GEBusMessageCommands.Commands.WRITE and endpoint == 0x39
            )
        except StopIteration:
            return

        sample_commands_future.set_result(
            (knobs_state_data, int.from_bytes(unknown, "big"))
        )

    try:
        knobs_state_data, unknown = await sample_commands_future
    finally:
        protocol.events.off("packet:ge", on_packet)

    # We parse the knobs state so that we can simulate a few buttons being pressed
    f = BytesIO(knobs_state_data)
    num_interactions_in_packet = int.from_bytes(read_exactly(f, 1), "big")
    num_interactions = int.from_bytes(read_exactly(f, 1), "big")
    unknown2 = int.from_bytes(read_exactly(f, 1), "big")

    knobs_state = [
        StackedWasherControls.Events(s)
        for s in read_exactly(f, 10)[:num_interactions_in_packet]
    ]
    trailer = read_exactly(f, 1)

    LOGGER.info(
        "Knobs board replied with packet #%r with unknown %r and state %r",
        num_interactions,
        unknown,
        knobs_state,
    )

    # Simulate a few button presses. This assumes we set the knobs to their correct
    # positions.
    for interaction in [
        StackedWasherControls.Events.BUTTON_START_RELEASED,
        StackedWasherControls.Events.BUTTON_START_PRESSED,
        # Pressing the deep rinse button is necessary only to wake it up.
        # Ideally, we should check to see if the machine is awake is active beforehand
        StackedWasherControls.Events.BUTTON_DEEP_RINSE_RELEASED,
        StackedWasherControls.Events.BUTTON_DEEP_RINSE_PRESSED,
    ][::-1]:
        # Send these one at a time
        num_interactions = (num_interactions + 1) % 0xFF
        knobs_state = [interaction] + knobs_state[:9]

        knobs_state_packet = b""
        knobs_state_packet += max(num_interactions, 10).to_bytes(
            1, "big"
        )  # Number of interactions in this packet
        knobs_state_packet += num_interactions.to_bytes(
            1, "big"
        )  # Total number of interactions
        knobs_state_packet += unknown2.to_bytes(
            1, "big"
        )  # Always 0x01. Maybe set if the controller knows its own state?
        knobs_state_packet += bytearray([e.value for e in knobs_state])

        knobs_state_packet += trailer

        try:
            await protocol.send_ge_message(
                GEBusPacket(
                    source=0x2D,
                    destination=0x23,
                    command=0xF1,
                    data=GEBusMessageCommands(
                        [
                            (
                                GEBusMessageCommands.Commands.WRITE,
                                0x2E,
                                knobs_state_packet,
                            ),
                            (
                                GEBusMessageCommands.Commands.WRITE,
                                0x39,
                                num_interactions.to_bytes(1, "big"),
                            ),  # Min packet ID??
                        ]
                    ).to_bytes(),
                ),
                retry=1,
                timeout=0.1,
            )
        except CasseroleError:
            pass

    # Finally, reset the counter. This gets the controller board to respect the knobs
    for num_interactions in [0xFE, 0xFF, 0x00, 0x01]:
        knobs_state_packet = b""
        knobs_state_packet += max(num_interactions, 10).to_bytes(
            1, "big"
        )  # Number of interactions in this packet
        knobs_state_packet += num_interactions.to_bytes(
            1, "big"
        )  # Total number of interactions
        knobs_state_packet += unknown2.to_bytes(
            1, "big"
        )  # Always 0x01. Maybe set if the controller knows its own state?
        knobs_state_packet += bytearray([e.value for e in knobs_state])

        knobs_state_packet += trailer

        try:
            await protocol.send_ge_message(
                GEBusPacket(
                    source=0x2D,
                    destination=0x23,
                    command=0xF1,
                    data=GEBusMessageCommands(
                        [
                            (
                                GEBusMessageCommands.Commands.WRITE,
                                0x2E,
                                knobs_state_packet,
                            ),
                            (
                                GEBusMessageCommands.Commands.WRITE,
                                0x39,
                                num_interactions.to_bytes(1, "big"),
                            ),  # Min packet ID??
                        ]
                    ).to_bytes(),
                ),
                retry=1,
                timeout=0.1,
            )
        except CasseroleError:
            pass

    await asyncio.sleep(100000)


async def main(adapter):
    loop = asyncio.get_event_loop()
    transport, protocol = await serial_asyncio.create_serial_connection(
        loop, CasseroleProtocol, adapter, baudrate=115200
    )

    while not protocol.transport:
        LOGGER.info("Waiting to connect...")
        await asyncio.sleep(1)

    await protocol.ping()

    LOGGER.info("Sending a broadcast to identify devices...")
    # Green Bean uses 0x1B as the source so I picked 0x1C
    response = await protocol.send_ge_message(
        GEBusPacket(source=0x1C, destination=0xFF, command=0x01, data=b""),
        retry=5,
        timeout=2,
    )
    address, version = response.source, response.data

    LOGGER.info("Found an appliance version %r at 0x%0.2X", version, address)

    while True:
        await asyncio.sleep(100000)


if __name__ == "__main__":
    coloredlogs.install(level="SPAM")

    if len(sys.argv) != 1:
        print(f"Usage: {__file__} <serial device>")
        sys.exit(1)

    asyncio.run(main(sys.argv[1]))
