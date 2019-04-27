#include <assert.h>
#include <Arduino.h>

class BusReaderResult {
	public:
		enum State {INVALID, READING, VALID};

	public:
		State result;
		char message[16];
};


class BusReaderState {
	public:
		static constexpr uint16_t MAX_PACKET_SIZE = 128;

	public:
		uint16_t crc16;
		uint8_t body[MAX_PACKET_SIZE + 10];
		int16_t size;

		bool escape_next_byte;

	public:
		BusReaderState() {
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

			return (int16_t)size > expected_size;
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

			crc16 = 0xE300;  // CRC initial value
		}
};


BusReaderResult read_bus_byte(BusReaderState &state, Stream &stream) {
	/*
	 * This function is called every loop and handles the parsing logic for the packet.
	 * It produces a partially-decoded packet that can be encapsulated and sent off.
	 * The packet is only checked superficially for correctness (i.e. size and CRC-16).
	 */
	uint8_t byte = stream.read();

	// XXX: Some messages don't end with an E1 so it gets mistakenly moved to the next packet.
	if ((state.size == 0) && (byte == 0xE1)) {
		return BusReaderResult{BusReaderResult::State::READING, "Ignoring E1"};
	}

	// If the packet is too big, discard it
	if (state.is_too_big()) {
		return BusReaderResult{BusReaderResult::State::INVALID, "Too big"};
	}

	// We keep track of this in a flag because it's not enough to look at the preceding byte. For example:
	//    ... E0 E0 E0
	// Here, the final E0 could either be a literal E0 or the start of an escape sequence. We cannot know unless we keep 
	// track of all of them somehow.
	if (state.escape_next_byte) {
		// Only E[0-3] need to be escaped
		if (byte != 0xE0 && byte != 0xE1 && byte != 0xE2 && byte != 0xE3) {
			// We can't escape an unescapable byte. Discard
			return BusReaderResult{BusReaderResult::State::INVALID, "Bad escape"};
		}

		// Write the escapable byte normally
		state.add_byte(byte);

		// This flag is turned off for the next byte
		state.escape_next_byte = false;

		return BusReaderResult{BusReaderResult::State::READING, "Read escaped"};
	} else if (byte == 0xE0) {
		// Escape the next byte but don't write this current one, since it's not included in the CRC or the length
		state.escape_next_byte = true;

		return BusReaderResult{BusReaderResult::State::READING, "Read escape"};
	} else if (byte == 0xE2) {
		// Start of a packet
		if (state.size > 0) {
			return BusReaderResult{BusReaderResult::State::INVALID, "Unexpected E2"};
		}

		state.add_byte(byte);

		return BusReaderResult{BusReaderResult::State::READING, "Read E2"};
	} else if (byte == 0xE3) {
		state.add_byte(byte);
		// End of packet

		// Ensure we've read exactly the right number of bytes
		if (state.get_size_from_header() != state.size) {
			return BusReaderResult{BusReaderResult::State::INVALID, "Bad size"};
		}

		// Finally, check the CRC.
		// We CRC the packet's own big-endian CRC bytes because this CRC construction has the following property:
		//    crc(message || crc(message)) == 0x0000
		// Thus, the CRC of any valid message concatenated with its CRC will be the same fixed value.
		// This allows us to superficially validate packets without doing much parsing at all.
		if (state.crc16 != 0xCD4D) {
			return BusReaderResult{BusReaderResult::State::INVALID, "Bad CRC"};
		}

		// This packet is valid!
		return BusReaderResult{BusReaderResult::State::VALID, "OK"};
	}

	// Just a normal byte
	state.add_byte(byte);
	return BusReaderResult{BusReaderResult::State::READING, "Read body byte"};
}
