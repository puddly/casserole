#include <assert.h>

#include <Arduino.h>
#include <SoftwareSerial.h>


constexpr uint8_t COMM_PIN = 3;


SoftwareSerial ge_serial(COMM_PIN, COMM_PIN, true);  // inverted logic


class PacketReaderState {
	public:
		static constexpr uint32_t MIN_INTER_PACKET_DELAY = 100000;
		static constexpr uint16_t MAX_PACKET_SIZE = 256;

	public:
		uint8_t body[MAX_PACKET_SIZE];
		uint16_t size;

		bool escape_next_byte;

	public:
		uint8_t source_id;
		uint8_t expected_size;
		uint8_t destination_id;

		uint16_t current_crc16;

	public:
		PacketReaderState() {
			reset();
		}

		int16_t get_size_from_header() {
			// The size in the packet header is the total length of the packet minus one:
			//    len(E2 [src size dst] ... [crc1 crc2] E3 E1) - 1
			if (size < 3) {
				return -1;
			}

			return body[2];
		}

		int16_t get_crc16_offset() {
			int16_t real_size = get_size_from_header();

			if (real_size == -1) {
				return -1;
			}

			// This should always be true
			if (real_size < 3) {
				return -1;
			}

			return real_size - 3;
		}

		int32_t get_crc16_from_footer() {
			int16_t real_size = get_size_from_header();

			if (real_size == -1) {
				return -1;
			}

			// The checksum starts at offset real_size - 3 and ends at real_size - 2
			if (size + 2 < real_size) {
				return -1;
			}

			// Big-endian
			return ((uint16_t)(body[real_size - 3] << 8)) | ((uint16_t)(body[real_size - 2] << 0));
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
		}

		void add_crc_byte(uint8_t byte) {
			current_crc16 ^= ((uint16_t)byte) << 8;

			for (uint8_t i = 0; i < 8; i++) {
				if ((current_crc16 & 0b1000000000000000) == 0) {
					current_crc16 <<= 1;
				} else {
					current_crc16 <<= 1;
					current_crc16 ^= 0x1021;  // polynomial
				}
			}
		}

		void reset() {
			size = 0;
			escape_next_byte = false;

			source_id = 0;
			expected_size = 0;
			destination_id = 0;

			current_crc16 = 0xE300;  // initial value
		}
};


enum PacketReaderResult {INVALID, READING, VALID};


PacketReaderResult maybe_process_packet_byte(PacketReaderState &state, Stream &stream) {
	/*
	 * This function is called every loop and handles the parsing logic for the packet.
	 * It produces a partially-decoded packet that can be encapsulated and sent off.
	 * The packet is only checked superficially for correctness (i.e. size and CRC-16).
	 */
	if (!stream.available()) {
		return PacketReaderResult::READING;
	}

	uint8_t byte = stream.read();

	// If the packet is too big, discard it
	if (state.is_too_big()) {
		return PacketReaderResult::INVALID;
	}

	// We keep track of this in a flag because it's not enough to look at the preceding byte. For example:
	//    ... E0 E0 E0
	// Here, the final E0 could either be a literal E0 or the start of an escape sequence. We cannot know unless we keep 
	// track of all of them somehow.
	if (state.escape_next_byte) {
		// This flag is turned off at the byte following the escape byte
		state.escape_next_byte = false;

		// Only E[0-3] need to be escaped
		if (byte == 0xE0 || byte == 0xE1 || byte == 0xE2 || byte == 0xE3) {
			// Write the escapable byte normally
			state.add_byte(byte);
			state.add_crc_byte(byte);

			return PacketReaderResult::READING;
		} else {
			// We can't escape an unescapable byte. Discard
			return PacketReaderResult::INVALID;
		}
	} else if (byte == 0xE0) {
		// Escape the next byte but don't write this current one, since it's not included in the CRC or the length
		state.escape_next_byte = true;

		return PacketReaderResult::READING;
	} else if (byte == 0xE1) {
		// End of packet

		// Ensure we've read exactly the right number of bytes
		if (state.get_size_from_header() != state.size) {
			return PacketReaderResult::INVALID;
		}

		// The second-to-last byte (in this case last-read) is always 0xE3
		if (state.body[state.size - 1] != 0xE3) {
			return PacketReaderResult::INVALID;
		}

		/*
		// Finally, check the CRC
		if (state.current_crc16 != state.get_crc16_from_footer()) {
			return PacketReaderResult::INVALID;
		}
		*/

		// This packet is valid!
		return PacketReaderResult::VALID;
	} else if (byte == 0xE2) {
		// Start of a packet
		state.reset();

		// It's not needed but is used as part of the CRC and including it makes offset logic simpler
		state.add_byte(byte);
		state.add_crc_byte(byte);

		return PacketReaderResult::READING;
	} else if (byte == 0xE3) {
		// I'm not sure what it's for but it's always the second to last byte
		state.add_byte(byte);

		return PacketReaderResult::READING;
	} else {
		// Just a normal byte
		state.add_byte(byte);

		// Don't include anything starting at or after the checksum bytes in the checksum
		if (state.size < 1 + state.get_crc16_offset()) {
			state.add_crc_byte(byte);
		}
	}

	return PacketReaderResult::READING;
}




void setup() {
	// Open serial communications and wait for the port to open
	Serial.begin(115200);

	while (!Serial) {
		// Hardware serial isn't ready yet
	}

	digitalWrite(COMM_PIN, LOW);  // It helps?
	ge_serial.begin(19200);

	// Helps prevent garbage at beginning somehow
	delay(500);
}

void loop() {
	static PacketReaderState reader_state;

	PacketReaderResult read_result = maybe_process_packet_byte(reader_state, ge_serial);

	if (read_result == PacketReaderResult::INVALID) {
		reader_state.reset();
	} else if (read_result == PacketReaderResult::READING) {
		// Do nothing
	} else if (read_result == PacketReaderResult::VALID) {
		// We have a valid packet!

		// Send it out
		Serial.write((uint8_t)((reader_state.size & 0x00FF) >> 0));
		Serial.write((uint8_t)((reader_state.size & 0xFF00) >> 8));
		Serial.write(reader_state.body, reader_state.size);
	} else {
		assert(0);  // This cannot happen
	}
}
