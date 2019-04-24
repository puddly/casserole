#include <assert.h>

#include <Arduino.h>
#include "SoftwareSerial/SoftwareSerial.h"

#include "reader.h"
#include "writer.h"


constexpr uint32_t BUS_BAUD = 19200;
constexpr uint8_t COMM_PIN = 3;

constexpr uint8_t CASSEROLE_SERVER_RX_BUS_MESSAGE_ID = 0x01;
constexpr uint8_t CASSEROLE_SERVER_TX_SERIAL_ID = 0x02;
constexpr uint8_t CASSEROLE_SERVER_RX_BUS_ERROR_ID = 0x03;
constexpr uint8_t CASSEROLE_SERVER_TX_SERIAL_ACK = 0x0F;
constexpr uint8_t CASSEROLE_CLIENT_SEND_BUS_MESSAGE_ID = 0x11;
constexpr uint8_t CASSEROLE_SERVER_DEBUG = 0xDE;

SoftwareSerial ge_serial(COMM_PIN, COMM_PIN, true);  // inverted logic


void write_casserole_message(Stream &stream, uint8_t type, uint16_t size, uint8_t *payload) {
	stream.write((uint8_t)((size & 0xFF00) >> 8));
	stream.write((uint8_t)((size & 0x00FF) >> 0));
	stream.write(type);
	stream.write(payload, size);

	// Timing for these messages isn't that important
	//stream.flush();
}

void uint32_to_bytes(uint8_t* buffer, uint32_t &n) {
	buffer[0] = (uint8_t)((n & 0xFF000000) >> 24);
	buffer[1] = (uint8_t)((n & 0x00FF0000) >> 16);
	buffer[2] = (uint8_t)((n & 0x0000FF00) >>  8);
	buffer[3] = (uint8_t)((n & 0x000000FF) >>  0);
}


void setup() {
	// Open serial communications and wait for the port to open
	Serial.begin(115200);

	while (!Serial) {
		// Hardware serial isn't ready yet
	}

	// Having RX == TX == COMM_PIN doesn't actually work. It defaults to RX only as an implementation detail.
	ge_serial.setRX(COMM_PIN);
	ge_serial.begin(BUS_BAUD);

	delay(500);
}

void loop() {
	/*
	 * Read a packet from the bus
	 */
	static PacketReaderState reader_state;
	static uint32_t last_byte_time = 0;

	uint32_t now = millis();

	PacketReaderResult read_result = maybe_read_bus_byte(reader_state, ge_serial);

	if (read_result.result == PacketReaderResult::INVALID) {
		last_byte_time = now;

		// Send out an error
		write_casserole_message(Serial, CASSEROLE_SERVER_RX_BUS_ERROR_ID, strlen(read_result.message), (uint8_t*)read_result.message);

		reader_state.reset();
	} else if (read_result.result == PacketReaderResult::WAITING) {
		// Do nothing
	} else if (read_result.result == PacketReaderResult::READING) {
		last_byte_time = now;
	} else if (read_result.result == PacketReaderResult::VALID) {
		// We have a valid packet!
		last_byte_time = now;

		// Send it out
		write_casserole_message(Serial, CASSEROLE_SERVER_RX_BUS_MESSAGE_ID, reader_state.size, reader_state.body);
	} else {
		assert(0);  // This cannot happen
	}

	// Keep track of the last byte's timestamp
	uint32_t bus_delta = now - last_byte_time;



	/*
	 * Read a packet from the serial connection and send it to the bus, if possible
	 */
	static PacketWriterState writer_state;

	// We sometimes won't have time to send a packet this loop iteration
	static PacketWriterResult write_result = PacketWriterResult::INVALID;

	if (write_result == PacketWriterResult::VALID) {
		if (bus_delta < 500) {
			// Don't change the state, just wait
		} else {
			// Briefly switch the software serial to TX mode and write the packet
			ge_serial.setTX(COMM_PIN);
			ge_serial.write(writer_state.body, writer_state.size);
			ge_serial.flush();  // SoftwareSerial has no TX buffering but this won't hurt in case we swap it out later
			ge_serial.setRX(COMM_PIN);

			write_casserole_message(Serial, CASSEROLE_SERVER_TX_SERIAL_ID, 0x00, nullptr);

			writer_state.reset();
			write_result = PacketWriterResult::INVALID;
		}
	} else {
		// Otherwise, read something
		write_result = maybe_read_serial_byte(writer_state, Serial);

		if (write_result == PacketWriterResult::READING) {
			// Do nothing
		} else if (write_result == PacketWriterResult::WAITING) {
			// Do nothing
		} else if (write_result == PacketWriterResult::INVALID) {
			writer_state.reset();
		} else if (write_result == PacketWriterResult::VALID) {
			// Do nothing until the next iteration
		} else {
			assert(0);
		}
	}
}
