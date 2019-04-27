#include <Arduino.h>

#include "SoftwareSerial/SoftwareSerial.h"

//#include "AltSoftSerial/AltSoftSerial.h"
//#include "AltSoftSerial/config/AltSoftSerial_Boards.h"
//#include "AltSoftSerial/config/AltSoftSerial_Timers.h"

#include "bus_reader.h"
#include "serial_reader.h"


constexpr uint32_t BUS_BAUD = 19200;
constexpr uint32_t BUS_SEND_DELAY_MICROS = 10000;  // min. quiet time before transmitting

// These two pins are tied together
constexpr uint8_t COMM_RX_PIN = 8;
constexpr uint8_t COMM_TX_PIN = 9;


namespace CasseroleMessage {
	// Server -> Client
	constexpr uint8_t BUS_MESSAGE = 0x01;
	constexpr uint8_t BUS_ERROR = 0x03;

	// Client -> Server
	constexpr uint8_t SEND_BUS_MESSAGE = 0x11;
	constexpr uint8_t SEND_BUS_MESSAGE_ACK = 0x12;

	constexpr uint8_t SEND_BUS_MESSAGE_TX = 0x02;

	// Misc
	constexpr uint8_t PING = 0xFF;
	constexpr uint8_t HEARTBEAT = 0xFE;
	constexpr uint8_t DEBUG = 0xDE;
};


SoftwareSerial ge_serial(COMM_RX_PIN, COMM_TX_PIN, true);  // inverted logic


void send_to_computer(uint8_t type, uint16_t size, uint8_t *payload) {
	Serial.write((uint8_t)((size & 0xFF00) >> 8));
	Serial.write((uint8_t)((size & 0x00FF) >> 0));
	Serial.write(type);

	if (size > 0) {
		Serial.write(payload, size);
	}

	// Timing for these messages isn't that important
	Serial.flush();
}

void setup() {
	// Open serial communications and wait for the port to open
	Serial.begin(19200);

	while (!Serial) {
		// Hardware serial isn't ready yet
	}

	ge_serial.begin(BUS_BAUD);

	digitalWrite(COMM_TX_PIN, LOW);
	pinMode(COMM_RX_PIN, INPUT);  // Disable the AltSoftSerial pullup
	pinMode(COMM_TX_PIN, INPUT);  // Disable TX until we enable it

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
				//send_to_computer(CasseroleMessage::DEBUG, strlen(bus_read_result.message), (uint8_t*)bus_read_result.message);
				break;

			case BusReaderResult::READING:
				// Do nothing
				//send_to_computer(CasseroleMessage::DEBUG, strlen(bus_read_result.message), (uint8_t*)bus_read_result.message);
				break;

			case BusReaderResult::VALID:
				// We have a valid packet!
				// Send it out
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
	static SerialReaderState serial_reader_state;	

	if (waiting_to_send) {
		switch (serial_reader_state.get_type_from_header()) {
			case CasseroleMessage::PING:
				send_to_computer(CasseroleMessage::PING, 0x00, nullptr);

				serial_reader_state.reset();
				waiting_to_send = false;
				break;

			case CasseroleMessage::SEND_BUS_MESSAGE:
				// We can't send anything until it's been quiet for enough time
				if (bus_delta < BUS_SEND_DELAY_MICROS) {
					break;
				}

				ge_serial.stopListening();

				// Enable TX
				digitalWrite(COMM_TX_PIN, LOW);
				pinMode(COMM_TX_PIN, OUTPUT);

				ge_serial.write(serial_reader_state.body + 3, serial_reader_state.size - 3);

				// Disable TX
				digitalWrite(COMM_TX_PIN, LOW);
				pinMode(COMM_TX_PIN, INPUT);

				ge_serial.listen();

				// We just sent a packet so reset it
				last_byte_time = micros();
				send_to_computer(CasseroleMessage::SEND_BUS_MESSAGE_TX, 0x00, nullptr);

				serial_reader_state.reset();
				waiting_to_send = false;
				break;

			default:
				// Invalid message type, discard
				serial_reader_state.reset();
				waiting_to_send = false;
				break;
		}
	} else {
		if (Serial.available()) {
			// Otherwise, read something
			SerialReaderResult serial_read_result = read_serial_byte(serial_reader_state, Serial);

			uint8_t result[2];

			if (serial_read_result == SerialReaderResult::READING) {
				// Do nothing
			} else if (serial_read_result == SerialReaderResult::INVALID) {
				serial_reader_state.reset();
			} else if (serial_read_result == SerialReaderResult::VALID) {
				// Handle this case above
				waiting_to_send = true;
				send_to_computer(CasseroleMessage::SEND_BUS_MESSAGE_ACK, 0x00, nullptr);
			} else {
				send_to_computer(CasseroleMessage::DEBUG, 1, result);
				assert(false);
			}
		}
	}
}
