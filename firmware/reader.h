#include <assert.h>

#include <Arduino.h>
#include <SoftwareSerial.h>

class PacketReaderResult {
	public:
		enum State {INVALID, WAITING, READING, VALID};

	public:
		State result;
		char message[16];
};


class PacketReaderState {
	public:
		static constexpr uint32_t MIN_INTER_PACKET_DELAY = 100000;
		static constexpr uint16_t MAX_PACKET_SIZE = 256;

	public:
		uint16_t crc16;
		uint8_t body[MAX_PACKET_SIZE];
		uint16_t size;

		bool escape_next_byte;

	public:
		PacketReaderState() {
			reset();
		}

		int16_t get_size_from_header() {
			// The size in the packet header is the total length of the packet:
			//    E2 [src size dst] ... [crc1 crc2] E3 E1
			if (size < 3) {
				return -1;
			}

			return body[2];
		}

		bool is_too_big() {
			int16_t expected_size = get_size_from_header();

			// We don't know yet
			if (expected_size == -1) {
				return false;
			}

			return size > expected_size;
		}

		void add_byte(uint8_t byte) {
			if (size >= MAX_PACKET_SIZE) {
				return;
			}

			body[size++] = byte;

			// Add the byte to our CRC
			crc16 ^= ((uint16_t)byte) << 8;

			for (uint8_t i = 0; i < 8; i++) {
				if ((crc16 & 0b1000000000000000) == 0) {
					crc16 <<= 1;
				} else {
					crc16 <<= 1;
					crc16 ^= 0x1021;  // polynomial
				}
			}
		}

		void reset() {
			size = 0;
			escape_next_byte = false;

			crc16 = 0xE300;
		}
};


PacketReaderResult maybe_read_bus_byte(PacketReaderState &state, Stream &stream) {
	/*
	 * This function is called every loop and handles the parsing logic for the packet.
	 * It produces a partially-decoded packet that can be encapsulated and sent off.
	 * The packet is only checked superficially for correctness (i.e. size and CRC-16).
	 */
	if (!stream.available()) {
		return PacketReaderResult{PacketReaderResult::State::WAITING, "No data"};
	}

	uint8_t byte = stream.read();

	// If the packet is too big, discard it
	if (state.is_too_big()) {
		return PacketReaderResult{PacketReaderResult::State::INVALID, "Too big"};
	}

	// We keep track of this in a flag because it's not enough to look at the preceding byte. For example:
	//    ... E0 E0 E0
	// Here, the final E0 could either be a literal E0 or the start of an escape sequence. We cannot know unless we keep 
	// track of all of them somehow.
	if (state.escape_next_byte) {
		// Only E[0-3] need to be escaped
		if (byte != 0xE0 && byte != 0xE1 && byte != 0xE2 && byte != 0xE3) {
			// We can't escape an unescapable byte. Discard
			return PacketReaderResult{PacketReaderResult::State::INVALID, "Bad escape"};
		}

		// Write the escapable byte normally
		state.add_byte(byte);

		// This flag is turned off for the next byte
		state.escape_next_byte = false;

		return PacketReaderResult{PacketReaderResult::State::READING, "Read escaped"};
	} else if (byte == 0xE0) {
		// Escape the next byte but don't write this current one, since it's not included in the CRC or the length
		state.escape_next_byte = true;

		return PacketReaderResult{PacketReaderResult::State::READING, "Read escape"};
	} else if (byte == 0xE1) {
		// End of packet

		// Ensure we've read exactly the right number of bytes
		if (state.get_size_from_header() != state.size) {
			return PacketReaderResult{PacketReaderResult::State::INVALID, "Bad size"};
		}

		// Finally, check the CRC.
		// We CRC the packet's own big-endian CRC bytes because this CRC construction has the following property:
		//    crc(message || crc(message)) == 0x0000
		// Thus, the CRC of any valid message will be the same fixed value. This allows us to parse the packet less.
		if (state.crc16 != 0xCD4D) {
			return PacketReaderResult{PacketReaderResult::State::INVALID, "Bad CRC"};
		}

		// This packet is valid!
		return PacketReaderResult{PacketReaderResult::State::VALID, "OK"};
	} else if (byte == 0xE2) {
		// Start of a packet
		state.reset();
		state.add_byte(byte);

		return PacketReaderResult{PacketReaderResult::State::READING, "Read E2"};
	} else if (byte == 0xE3) {
		// I'm not sure what it's for but it's always the second to last byte
		state.add_byte(byte);

		return PacketReaderResult{PacketReaderResult::State::READING, "Read E3"};
	} else {
		// Just a normal byte
		state.add_byte(byte);
		return PacketReaderResult{PacketReaderResult::State::READING, "Read body byte"};
	}

	// We can't get here
	assert(false);
}
