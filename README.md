# Casserole
This is my attempt at creating an open source alternative to the now-defunct [Green Bean adapter](https://github.com/GEMakers/green-bean). I'm not much of a hardware hacker and I could be reverse engineering a well-known protocol, so please let me know if you recognize what this is.

## RJ45 Port
The RJ45 (Ethernet) port on certain GE appliances exposes a bus that allows for communication with the appliance's controller board. The three pins are labeled `GND`, `COMM`, and `9V`.

The COMM bus uses 5V logic and is an *inverted* logic UART at 19,200 baud. Interestingly, the dials and buttons on my washer are hooked into a small board that hooks into this same bus.


## Communication
You can easily communicate with it with Arduino's `SoftwareSerial` and an adapter board that can tolerate 5V on its inputs (NodeMCU, some Arduino Pro Minis, etc.):

```C++
#include <SoftwareSerial.h>

#define COMM_PIN  5  // replace with whatever pin you use

SoftwareSerial ge_serial(COMM_PIN, COMM_PIN, true);

void setup() {
	Serial.begin(115200);

	while (!Serial) {}

	ge_serial.begin(19200);
}

void loop() {
	if (ge_serial.available()) {
		Serial.write(ge_serial.read());
	}
}
```

## Protocol
I've been unable to acquire an actual Green Bean module so all of my observations are based on inspecting the data sent through the bus. Here is a sample packet:

    e2 23 22 2d f1 03 f1 2e 0e 03 03 01 19 15 05 2a 00 0a f1 76 fc 0f 0a f1 39 01 03 f1 33 01 5d 9c 30 e3 e1

All packets begin with `e2` and end with `e1`. The byte `e0` acts as an escape character and all instances of `e0`, `e1`, `e2`, and `e3` in the body of the packet are escaped with `e0` (so `aa e0 bb e1 cc` becomes `aa e0 e0 bb e0 e1 cc`)

Each packet appears to have an eight byte header:

 - (1 byte) packet sender's ID (`0x23` for the knob board, `0x2d` for the controller board)
 - (1 byte) total packet length
 - (1 byte) packet destination's ID
 - (4 bytes) packet ID?
 - (1 byte) command ID

My washer seems to have three useful commands:

 - `0x01`: sent from the controller to the knob board indicating some sort of washer state.
 - `0x0e`: sent from the knob board to the controller every second and whenever a knob is turned or a button is pushed/released.
 - `0xf1`: sent in reply to any of the above messages, most likely an ACK.

Each packet ends with:

 - (2 bytes) a hash. It appears to be non-cryptographic and possibly similar in structure to [Fletcher-16](https://en.wikipedia.org/wiki/Fletcher%27s_checksum#Fletcher-16).
 - (2 bytes) `e3 e1`. Occasionally I see only `e3` but I suspect that may be a transmission error.

## TODO

 - Identify the hash. Without this, 65,536 possible checksums need to be tried to find the correct one.
 - Figure out how to safely begin injecting commands without interrupting other communications.
 - Build a tool to reliably dump traffic from the bus.
 - Create a new [GEA adapter](https://github.com/GEMakers/gea-adapter-usb) so that the open source GEA SDK can be used.
