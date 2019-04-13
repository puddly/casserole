#include <Arduino.h>
#include <SoftwareSerial.h>

#if defined(ARDUINO_AVR_MEGA)
	#define COMM_PIN  13
#elif defined(ARDUINO_AVR_PRO)
	#define COMM_PIN  3
#elif defined(ESP8266)
	#include <ESP8266WiFi.h>

	// The NodeMCU is actually 5V tolerant
	#define COMM_PIN  D5
#else
	#error "Unsupported board"
#endif


SoftwareSerial ge_serial(COMM_PIN, COMM_PIN, true);  // inverted logic


void setup() {
	#if defined(ESP8266)
		// Disable WiFi for now
		WiFi.forceSleepBegin();
		delay(10);
	#endif

	// Open serial communications and wait for port to open:
	Serial.begin(115200);

	while (!Serial) {
		// Hardware serial isn't ready yet
	}

	ge_serial.begin(19200);
}

class Packet {
	public:
		static constexpr uint32_t MIN_INTER_PACKET_DELAY = 12000;
		static constexpr uint16_t MAX_PAYLOAD_SIZE = 300;

	public:
		uint32_t timestamp;
		uint16_t size;
		uint8_t buffer[MAX_PAYLOAD_SIZE];

	public:
		Packet() {
			reset();
		}

		void reset() {
			timestamp = 0;
			size = 0;
		}

		void write(uint8_t byte) {
			buffer[size++] = byte;
		}

		bool is_full() {
			return size >= MAX_PAYLOAD_SIZE;
		}

		void send() {
			// Sync header (doesn't appear in any packet due to escaping)
			Serial.write(0xE1);
			Serial.write(0xE2);
			Serial.write(0xE3);
			Serial.write(0xE2);
			Serial.write(0xE1);

			// Timestamp
			Serial.write((uint8_t)((timestamp & 0x000000FF) >>  0));
			Serial.write((uint8_t)((timestamp & 0x0000FF00) >>  8));
			Serial.write((uint8_t)((timestamp & 0x00FF0000) >> 16));
			Serial.write((uint8_t)((timestamp & 0xFF000000) >> 24));

			// Size
			Serial.write((uint8_t)((size & 0x00FF) >>  0));
			Serial.write((uint8_t)((size & 0xFF00) >>  8));

			// Data
			Serial.write(buffer, size);
		}
};

#if defined(PASSTHROUGH)
	void loop() {
		if (ge_serial.available()) {
			Serial.write(ge_serial.read());
		}

		if (Serial.available()) {
			ge_serial.write(Serial.read());
		}
	}
#else
	void loop() {
		static Packet packet;
		static uint32_t last_byte_time = 0;

		uint32_t current_byte_time = micros();
		uint32_t delta = current_byte_time - last_byte_time;

		// If the packet is too big, discard it
		if (packet.is_full()) {
			packet.reset();
		}

		// If a new byte has not arrived in too long, discard it
		if (delta > Packet::MIN_INTER_PACKET_DELAY) {
			packet.reset();
		}

		// Otherwise, we are receiving a byte
		if (!ge_serial.available()) {
			return;
		}

		uint8_t byte = ge_serial.read();

		if (byte == 0xE0 || byte == 0xE1 || byte == 0xE2 || byte == 0xE3) {
			bool is_escaped = (packet.size >= 2) && (packet.buffer[packet.size - 2] == 0xE0);

			// Write the byte regardless, we only partially decode the packet for framing purposes
			packet.write(byte);

			if (is_escaped) {
				// Write it normally if the byte is already escaped
			} else if (byte == 0xE2) {
				// Start of a packet. Mark when this happens.
				packet.timestamp = current_byte_time;
			} else if (byte == 0xE1) {
				// End of packet, send it
				packet.send();
				packet.reset();
			}
		} else {
			// Regular data
			packet.write(byte);
		}

		last_byte_time = current_byte_time;
	}
#endif