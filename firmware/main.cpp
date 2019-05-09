#include <Arduino.h>
#include <HardwareSerial.h>

#include "bus_reader.h"
#include "serial_reader.h"


constexpr uint32_t SERIAL_BAUD = 115200;


// ESP-32 hardware serial
#define ge_serial Serial2

constexpr uint8_t BUS_RX_ENABLE_PIN = 32;
constexpr uint8_t BUS_TX_ENABLE_PIN = 33;

constexpr uint8_t BUS_RX_PIN = 16;
constexpr uint8_t BUS_TX_PIN = 17;

constexpr uint32_t BUS_BAUD = 19200;
constexpr uint32_t BUS_SEND_DELAY_MICROS = 13000;  // min. quiet time before transmitting


namespace CasseroleMessage {
	// Server -> Client
	constexpr uint8_t BUS_MESSAGE = 0x01;
	constexpr uint8_t BUS_ERROR = 0x03;

	// Client -> Server
	constexpr uint8_t SEND_BUS_MESSAGE = 0x11;
	constexpr uint8_t SEND_BUS_MESSAGE_ACK = 0x12;
	constexpr uint8_t SEND_BUS_MESSAGE_ERR = 0x13;

	constexpr uint8_t SEND_BUS_MESSAGE_TX = 0x02;

	// Misc
	constexpr uint8_t PING = 0xFF;
	constexpr uint8_t HEARTBEAT = 0xFE;
	constexpr uint8_t DEBUG = 0xDE;
};


void send_to_computer(uint8_t type, uint8_t size, uint8_t *payload) {
	uint8_t buffer[0xFF];

	if (size > 0xFF - 4) {
		// This should not happen
		assert(false);
		return;
	}

	buffer[1] = (uint8_t)((size & 0xFF00) >> 8);
	buffer[2] = (uint8_t)((size & 0x00FF) >> 0);
	buffer[3] = type;

	for (uint8_t i = 0; i < size; i++) {
		buffer[4 + i] = payload[i];
	}

	buffer[4 + size] = 0x00;  // Trailing null byte

    uint8_t index_of_last_zero = 0;

    for (uint8_t offset = 1; offset < size + 4; offset++) {
        if (buffer[offset] == 0x00) {
            buffer[index_of_last_zero] = offset - index_of_last_zero;
            index_of_last_zero = offset;
        }
    }

    buffer[index_of_last_zero] = 4 + size - index_of_last_zero;

	Serial.write(buffer, 4 + size + 1);

	// Timing for these messages isn't that important
	Serial.flush();
}

void send_to_computer(uint8_t type) {
	send_to_computer(type, 0x00, nullptr);
}

void set_transmit(bool tx) {
	// inverted logic, so LOW=enabled, HIGH=disabled
	if (tx) {
		digitalWrite(BUS_RX_ENABLE_PIN, HIGH);
		digitalWrite(BUS_TX_ENABLE_PIN, LOW);
	} else {
		digitalWrite(BUS_TX_ENABLE_PIN, HIGH);
		digitalWrite(BUS_RX_ENABLE_PIN, LOW);
	}
}

void setup() {
	Serial.begin(SERIAL_BAUD);

	while (!Serial) {
		// Hardware serial isn't ready yet
	}

	set_transmit(false);
	pinMode(BUS_RX_ENABLE_PIN, OUTPUT);
	pinMode(BUS_TX_ENABLE_PIN, OUTPUT);
	set_transmit(false);

	ge_serial.begin(BUS_BAUD, SERIAL_8N1, BUS_RX_PIN, BUS_TX_PIN);

	delay(500);
	send_to_computer(CasseroleMessage::PING);
	delay(500);
}


void loop() {
	/*
	 * Read a packet from the bus
	 */
	static BusReaderState bus_reader_state;
	static uint32_t last_byte_time = 0;

	uint32_t now = micros();

	// Only read if there is data to read
	if (ge_serial.available()) {
		last_byte_time = now;

		BusReaderResult bus_read_result = read_bus_byte(bus_reader_state, ge_serial);

		switch (bus_read_result.result) {
			case BusReaderResult::INVALID:
				// Send out an error
				send_to_computer(CasseroleMessage::BUS_ERROR, strlen(bus_read_result.message), (uint8_t*)bus_read_result.message);
				send_to_computer(CasseroleMessage::DEBUG, bus_reader_state.size, bus_reader_state.body);

				bus_reader_state.reset();
				break;

			case BusReaderResult::READING:
				// Do nothing
				break;

			case BusReaderResult::VALID:
				// We have a valid packet!
				send_to_computer(CasseroleMessage::BUS_MESSAGE, bus_reader_state.size, bus_reader_state.body);
				bus_reader_state.reset();
				break;

			default:
				assert(false);
				break;
		}
	}


	// Keep track of the last byte's timestamp
	uint32_t bus_delta = now - last_byte_time;



	/*
	 * Read a packet from the serial connection and send it to the bus, if possible
	 */

	// We sometimes won't have time to send a packet this loop iteration
	static bool waiting_to_send = false;
	static bool resync = false;
	static SerialReaderState serial_reader_state;

	if (waiting_to_send) {
		uint8_t payload_size = serial_reader_state.get_payload_size();
		uint8_t* payload = serial_reader_state.get_payload();

		switch (serial_reader_state.get_type_from_header()) {
			case CasseroleMessage::PING:
				send_to_computer(CasseroleMessage::PING);

				serial_reader_state.reset();
				waiting_to_send = false;
				break;

			case CasseroleMessage::SEND_BUS_MESSAGE:
				// We can't send anything until it's been quiet for enough time
				if (bus_delta < BUS_SEND_DELAY_MICROS) {
					break;
				}

				// Enable TX
				set_transmit(true);

				// Write the Header
				ge_serial.write(payload, 3);

				// We handle escaping/unescaping in here so the computer-side code never deals with it
				for (uint8_t i = 3; i < payload_size - 2; i++) {
					uint8_t byte = payload[i];

					if ((byte == 0xE0) || (byte == 0xE1) || (byte == 0xE2) || (byte == 0xE3)) {
						// Escape the byte before writing it
						ge_serial.write(0xE0);
					}

					ge_serial.write(byte);
				}

				// Write the footer
				ge_serial.write(payload + (payload_size - 2), 2);

				// Flush before we disable transmission
				ge_serial.flush();

				// Disable TX
				set_transmit(false);

				// We just sent a packet so reset the timer
				last_byte_time = micros();
				send_to_computer(CasseroleMessage::SEND_BUS_MESSAGE_TX);

				serial_reader_state.reset();
				waiting_to_send = false;
				break;

			default:
				// Invalid message type, discard
				send_to_computer(CasseroleMessage::SEND_BUS_MESSAGE_ERR);
				serial_reader_state.reset();
				waiting_to_send = false;
				break;
		}
	} else {
		if (Serial.available()) {
			uint8_t byte = Serial.read();

			if (resync) {
				// We use COBS to turn null bytes into frame delimiters
				if (byte == 0x00) {
					resync = false;
				}
			} else {
				SerialReaderResult serial_read_result = read_serial_byte(serial_reader_state, byte);

				if (serial_read_result.result == SerialReaderResult::READING) {
					// Do nothing
				} else if (serial_read_result.result == SerialReaderResult::INVALID) {
					serial_reader_state.reset();

					send_to_computer(CasseroleMessage::SEND_BUS_MESSAGE_ERR, strlen(serial_read_result.message), (uint8_t*)serial_read_result.message);

					// Something is wrong, wait until the next frame to try again
					resync = true;
				} else if (serial_read_result.result == SerialReaderResult::VALID) {
					// Handle this case above
					waiting_to_send = true;
					send_to_computer(CasseroleMessage::SEND_BUS_MESSAGE_ACK);
				} else {
					assert(false);
				}
			}
		}
	}
}
