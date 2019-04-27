# Casserole
This is my attempt at creating an open source alternative to the now-defunct [Green Bean adapter](https://github.com/GEMakers/green-bean).

## RJ45 Port
The RJ45 (Ethernet) port on some GE appliances exposes a bus that allows for communication with the appliance's controller board. The three pins are labeled `GND`, `COMM`, and `9V`.

The COMM bus uses 5V logic and is an *inverted* logic UART at 19,200 baud.

## Protocol
I've been unable to acquire an actual Green Bean module so all of the information here is based on what I can capture from my washing machine. Here is a sample packet:

    e2 23 22 2d f1 03 f1 2e 0e 03 03 01 19 15 05 2a 00 0a f1 76 fc 0f 0a f1 39 01 03 f1 33 01 5d 9c 30 e3 e1

All packets begin with `e2` and end with `e3 e1` (although very rarely just `e3`). The byte `e0` acts as an escape character and all instances of `e0`, `e1`, `e2`, and `e3` in the body of the packet are escaped with `e0` (so `aa e0 bb e1 cc` becomes `aa e0 e0 bb e0 e1 cc`).

Each packet has a simple structure:
 
 - (1 byte) `e2`
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

## TODO
 - Create a new [GEA adapter](https://github.com/GEMakers/gea-adapter-usb) so that the open source GEA SDK can be used.
