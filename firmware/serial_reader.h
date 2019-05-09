#include <Arduino.h>

class SerialReaderResult {
	public:
		enum State {INVALID, READING, VALID};

	public:
		State result;
		char message[16];
};

class SerialReaderState {
	public:
		static constexpr uint16_t MAX_PACKET_SIZE = 0xFF - 2;

	public:
		uint16_t crc16;
		uint8_t body[MAX_PACKET_SIZE + 10];
		uint8_t size;

		uint8_t bytes_until_next_null;

	public:
		SerialReaderState() {
			reset();
		}

		int16_t get_size_from_header() {
			if (size < 1) {
				return -1;
			}

			return body[0];
		}

		int16_t get_type_from_header() {
			if (size < 2) {
				return -1;
			}

			return body[1];
		}

		bool is_too_big() {
			int16_t expected_size = get_size_from_header();

			// We don't know yet
			if (expected_size == -1) {
				return false;
			}

			return size > (int8_t)expected_size;
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
			bytes_until_next_null = 0;
			size = 0;
			crc16 = 0xE300;  // CRC initial value
		}

		uint8_t* get_payload() {
			if (size < 3) {
				return nullptr;
			}

			return &body[2];
		}

		uint8_t get_payload_size() {
			return size - 2 - 2;
		}
};

SerialReaderResult read_serial_byte(SerialReaderState &state, uint8_t byte) {
	// Null bytes denote the end of each frame
	if (byte == 0x00) {
		// This must be 1 by the time we get to the end of a frame
		if (state.bytes_until_next_null != 1) {
			return SerialReaderResult{SerialReaderResult::INVALID, {state.bytes_until_next_null}};
		}

		int16_t expected_size = state.get_size_from_header();

		// Check that the size exists and is correct
		if ((expected_size == -1) || (state.size != expected_size)) {
			return SerialReaderResult{SerialReaderResult::INVALID, "Bad size"};
		}

		// Check the CRC to make sure it's valid
		if (state.crc16 != 0x0000) {
			return SerialReaderResult{SerialReaderResult::INVALID, "Bad CRC"};
		}

		return SerialReaderResult{SerialReaderResult::VALID, "OK"};
	}

	// We cannot validate anything at the start of a frame
	if ((state.size == 0) && (state.bytes_until_next_null == 0)) {
		state.bytes_until_next_null = byte;
		return SerialReaderResult{SerialReaderResult::READING, "Start"};
	}

	assert(state.bytes_until_next_null > 0);  // This cannot happen
	state.bytes_until_next_null--;

	if (state.bytes_until_next_null == 0) {
		state.bytes_until_next_null = byte;
		byte = 0x00;
	}

	state.add_byte(byte);

	int16_t expected_size = state.get_size_from_header();

	if (expected_size != -1) {
		// I don't think this is necessary since the next condition is stronger
		if (state.size > expected_size) {
			return SerialReaderResult{SerialReaderResult::INVALID, "Too big"};
		}

		// COBS can tell us mid-frame if we have a framing error if we've received the length already.
		// We ignore the null byte at the end, which increases the expected length by 1.
		if (state.size + state.bytes_until_next_null > expected_size + 1) {
			return SerialReaderResult{SerialReaderResult::INVALID, "Bad frame size"};
		}
	}

	return SerialReaderResult{SerialReaderResult::READING, "Reading"};
}