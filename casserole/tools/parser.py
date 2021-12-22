import sys

import coloredlogs
from verboselogs import VerboseLogger

from casserole.utils import pretty_bytes
from casserole.protocol import GEBusPacket
from casserole.exceptions import ParsingError, IncompleteReadError

LOGGER = VerboseLogger(__name__)


def parse_data(data: bytes):
    while data:
        skipped = data.index(GEBusPacket.START_OF_FRAME)

        if skipped > 0:
            LOGGER.warning(
                "Skipping first %d bytes: %s", skipped, pretty_bytes(data[:skipped])
            )
            data = data[skipped:]

        # LOGGER.info("Trying to parse              %s", pretty_bytes(data))

        try:
            packet, new_data = GEBusPacket.deserialize(data)
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
