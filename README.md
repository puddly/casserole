# Casserole
An open source alternative to the now-defunct [Green Bean adapter](https://github.com/GEMakers/green-bean) to monitor and control GE appliances through their RJ45 port.

# Installation

```sh
# Clone the repo
git clone https://github.com/puddly/casserole
cd casserole

# Setup a new virtual Python env (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Compile and upload the firmware to your ESP32
platformio run -t upload -v -e esp32 --upload-port=/dev/cu.SLAB_USBtoUART

# Run the host software and see what your appliance is doing
python protocol.py
```


## What works
1. All bus messages are sent back to the computer, including ones sent by the appliance user input boards.
2. Messages can be sent to the bus.

## What doesn't work
1. Other devices occasionally interrupt the adapter's messages. I'm not sure how devices take turns when sending data over the bus.
2. GE/FirstBuild's open source SDK is incomplete and does not document any way to remotely start some appliances (like my washer).

## Hardware
I don't know much about building electronics but here are the parts I've used:

 - ESP32 dev kit ([I use this one with built-in RGB LEDs](https://www.tindie.com/products/ddebeer/esp32-dev-board-wifibluetooth/) but any should work)
 - 3.3v to 5V bus transceiver ([TI SN74LVC2T45](https://www.ti.com/lit/ds/symlink/sn74lvc2t45.pdf))
 - 5V regulator ([ST LD1117](https://www.st.com/content/ccc/resource/technical/document/datasheet/99/3b/7d/91/91/51/4b/be/CD00000544.pdf/files/CD00000544.pdf/jcr:content/translations/en.CD00000544.pdf), though just about any should work). I've read that the ESP32 can draw up to 600mA in 100ms bursts when in AP mode but ordinarily draws about 40mA.

Wiring:

 - Regulate the 9V from the GE bus down to 5V and connect it both your ESP32's `Vin` pin and to the high voltage input of the bus transceiver.
 - Connect the ESP32's 3.3V pin to the low voltage input of the bus transceiver.
 - Tie together the ESP32's second UART's RX and TX pins (16 and 17) and connect them to the low voltage input of the bus transceiver.
 - Connect pin 18 (though any will work) to the direction control of the bus transceiver.

```
[insert proper diagram here]
```

## Low-level details

### RJ45 Port
The RJ45 (Ethernet) port on some GE appliances exposes a bus that allows for communication with the appliance's controller board. The three pins are labeled `GND`, `COMM`, and `9V`.

The COMM bus uses 5V logic and is an inverted UART at 19,200 baud.

### Protocol
I've been unable to acquire an actual Green Bean module so all of the information here is based on what I can capture from my washing machine. Here is a sample packet:

    e2 23 22 2d f1 03 f1 2e 0e 03 03 01 19 15 05 2a 00 0a f1 76 fc 0f 0a f1 39 01 03 f1 33 01 5d 9c 30 e3 e1

All packets begin with `e2` and end with `e3 e1` (although very rarely just `e3`). The byte `e0` acts as an escape character and all instances of `e0`, `e1`, `e2`, and `e3` in the body of the packet are escaped with `e0` (so `aa e0 bb e1 cc` becomes `aa e0 e0 bb e0 e1 cc`).

Each packet has a simple structure:
 
 - (1 byte) `e2`. Everything after this but before the final `e1` is encoded using the above scheme.
 - (1 byte) packet destination
 - (1 byte) total packet length (*before* the `e[0-3]` bytes have been escaped)
 - (1 byte) packet sender
 - (1 byte) command type
 - (? bytes) data
 - (2 bytes) CRC-16 checksum of the entire packet up until the start of the checksum bytes. It is a 16-bit CRC with the following parameters:

       width=16  poly=0x1021  init=0xe300  refin=false  refout=false  xorout=0x0000  check=0x5b10  residue=0x0000  name=(none)

    As before, this is computed on the packet payload before the `e[0-3]` bytes have been escaped. Interestingly, this specific CRC-16 has the following property:

       crc16(packet_until_checksum || crc16(packet_until_checksum)) == 0x0000

 - (1 or 2 bytes) `e1 e3`, although very rarely a packet is sent (consistently) with `e3` missing.

The packet command type determines how the `data` is interpreted. A command type of `f1` is used internally for all reads/writes and has the following structure:

 - (1 byte) `f1`
 - (1 byte) number of reads/writes encoded in `data`
 - A list of commands:
   - (1 byte) `f0` is read, `f1` is write.
   - (1 byte) endpoint ID
   - (1 byte) (This and the following bytes are absent in read requests and write acknowledgements) size of read respons or data to be written
   - (? bytes) data

The Green Bean uses a different syntax for reads (writes TBD) for what it calls ERDs:

 - (1 byte) `f0`
 - (1 byte) `01` for reads
 - (2 byte) 16-bit ERD, big-endian
