import sys

import coloredlogs
from verboselogs import VerboseLogger

from casserole.utils import pretty_bytes
from casserole.protocol import GEAFrame, ERDCommand, ERDCommandID
from casserole.exceptions import ParsingError, IncompleteReadError

LOGGER = VerboseLogger(__name__)


def parse_data(data: bytes):
    while data:
        skipped = data.index(GEAFrame.START_OF_FRAME)

        if skipped > 0:
            LOGGER.warning(
                "Skipping first %d bytes: %s", skipped, pretty_bytes(data[:skipped])
            )
            data = data[skipped:]

        # LOGGER.info("Trying to parse              %s", pretty_bytes(data))

        try:
            packet, new_data = GEAFrame.deserialize(data)
        except IncompleteReadError:
            break
        except ParsingError:
            LOGGER.warning("Failed to parse", exc_info=True)
            data = data[1:]
            continue

        parsed_chunk = data[: len(data) - len(new_data)]
        data = bytearray(new_data)

        LOGGER.debug("RX: %s", pretty_bytes(parsed_chunk))
        LOGGER.info("Parsed: %s", packet)

        if ERDCommandID.READ <= packet.payload[0] <= ERDCommandID.PUBLISH:
            try:
                command, remaining = ERDCommand.deserialize(packet.payload)
            except Exception:
                LOGGER.warning(
                    "Failed to parse ERD: %s",
                    pretty_bytes(packet.payload),
                    exc_info=True,
                )
                continue

            LOGGER.info("Parsed payload: %s", command)
            assert command.serialize() == packet.payload
        else:
            LOGGER.error("Unknown command: %02X", packet.payload[0])

    if data:
        LOGGER.warning("Did not parse trailing data: %s", pretty_bytes(data))


if __name__ == "__main__":
    coloredlogs.install(level="SPAM")

    data = bytearray()

    # Parse ESPHome logs directly
    for line in sys.stdin:
        if "uart_debug" in line:
            data.extend(bytes.fromhex(line.split(" <<< ", 1)[1]))

    parse_data(data)
