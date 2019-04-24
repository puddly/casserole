#include <assert.h>

#include <Arduino.h>
#include <SoftwareSerial.h>

enum class PacketWriterResult {INVALID, WAITING, READING, VALID};

class PacketWriterState {
	public:
		static constexpr uint16_t MAX_PACKET_SIZE = 256;

	public:
		uint8_t body[MAX_PACKET_SIZE];
		uint16_t size;

	public:
		PacketWriterState() {
			reset();
		}

		int16_t get_size_from_header() {
			if (size < 2) {
				return -1;
			}

			return (body[0] << 8) | (body[1] << 0);
		}

		int16_t get_type_from_header() {
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
		}

		void reset() {
			size = 0;
		}
};

PacketWriterResult maybe_read_serial_byte(PacketWriterState &state, Stream &stream) {
	if (!stream.available()) {
		return PacketWriterResult::WAITING;
	}

	uint8_t byte = stream.read();
	state.add_byte(byte);

	// If the packet is too big, discard it
	if (state.is_too_big()) {
		return PacketWriterResult::INVALID;
	}

	int16_t expected_size = state.get_size_from_header();

	if (expected_size != -1 && (int16_t)state.size == expected_size) {
		return PacketWriterResult::VALID;
	}

	return PacketWriterResult::READING;
}