#include <assert.h>

#include <Arduino.h>
#include <SoftwareSerial.h>

#include "reader.h"
#include "writer.h"


constexpr uint32_t BUS_BAUD = 19200;
constexpr uint8_t COMM_PIN = 3;

SoftwareSerial ge_serial(COMM_PIN, COMM_PIN, true);  // inverted logic


void setup() {
	// Open serial communications and wait for the port to open
	Serial.begin(115200);

	while (!Serial) {
		// Hardware serial isn't ready yet
	}

	digitalWrite(COMM_PIN, LOW);  // It helps?
	ge_serial.begin(BUS_BAUD);

	// Helps prevent garbage at beginning somehow
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

	if (read_result == PacketReaderResult::INVALID) {
		last_byte_time = now;

		reader_state.reset();
	} else if (read_result == PacketReaderResult::WAITING) {
		// Do nothing
	} else if (read_result == PacketReaderResult::READING) {
		last_byte_time = now;
	} else if (read_result == PacketReaderResult::VALID) {
		// We have a valid packet!
		last_byte_time = now;

		// Send it out
		Serial.write((uint8_t)((reader_state.size & 0xFF00) >> 8));
		Serial.write((uint8_t)((reader_state.size & 0x00FF) >> 0));
		Serial.write(0x01);  // 0x01 is data from the bus
		Serial.write(reader_state.body, reader_state.size);
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
		if (bus_delta <= PacketReaderState::MIN_INTER_PACKET_DELAY) {
			// Do nothing until we have time to send it
		} else {
			// Write the buffered packet to the bus (we skip the two size bytes and the type)
			ge_serial.write(writer_state.body + 3, writer_state.get_size_from_header());

			// Actually send out the data
			ge_serial.flush();

			// Tell the client we sent the data
			Serial.write((uint8_t)((0x0000 & 0xFF00) >> 8));
			Serial.write((uint8_t)((0x0000 & 0x00FF) >> 0));
			Serial.write(0x02);  // 0x02 is a sent notification

			// Reset the state so we can continue reading from serial the next iteration
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
			// This should be impossible but we can still handle it
			// Do nothing until the next iteration
		}
	}
}
