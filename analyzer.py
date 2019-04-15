import sys
import serial

from io import BytesIO
from collections import deque


def crc16(data):
    '''
    CRC parameters found with http://reveng.sourceforge.net/:
        width=16  poly=0x1021  init=0xe300  refin=false  refout=false  xorout=0x0000  check=0x5b10  residue=0x0000  name=(none)
    '''

    crc = 0xE300

    for b in data:
        crc ^= b << 8

        for j in range(0, 8):
            if crc & 0b1000000000000000:
                crc <<= 1
                crc ^= 0x1021
            else:
                crc <<= 1

            crc &= 0xFFFF

    return crc


class BadPacketError(ValueError):
    pass


def pretty_bytes(bytes_object):
    return ' '.join([hex(b)[2:].zfill(2) for b in bytes_object])


with serial.Serial(sys.argv[1], baudrate=115200) as ser:
    while True:
        try:
            size = int.from_bytes(ser.read(2), 'little')

            if size > 256:
                raise BadPacketError(f'Packet too large: {size} > 256')

            # We encapsulate the real packet in our own frame
            # This probably isn't necessary anymore
            inner_packet = ser.read(size)

            '''
            # Replace the escapes
            for byte in [b'\xE3', b'\xE2', b'\xE1', b'\xE0']:
                inner_packet = inner_packet.replace(b'\xE0' + byte, byte)
            '''

            buffer = BytesIO(inner_packet)

            # Structure
            #   e2 [1:source_id] [1:total_length] [1:dest_id] [4:transaction_id] [1:command] [???:escaped_payload] e3 [usually e1]
            #   escaped_payload has all e0, e1, e2, and e3 bytes escaped with e0

            '''
            # All packets start with E2
            packet_start = buffer.read(1)

            if packet_start != b'\xE2':
                print(f'Unknown packet start: {pretty_bytes(inner_packet)}')
                continue
            '''

            _ = buffer.read(1)  # The E2 byte
            source_addr = int.from_bytes(buffer.read(1), 'little')
            total_packet_length = int.from_bytes(buffer.read(1), 'little')
            dest_addr = int.from_bytes(buffer.read(1), 'little')

            payload = buffer.read(total_packet_length - 7)
            checksum = buffer.read(2)
            _ = buffer.read(1)  # The E1 byte

            if len(checksum) != 2:
                raise BadPacketError(f'Checksum is too short {pretty_bytes(checksum)}, {len(checksum)} != 2')

            # Hash the entire packet up until the start of the checksum itself
            if crc16(inner_packet[:-3]) != int.from_bytes(checksum, 'big'):
                raise BadPacketError(f'Checksum is invalid: {crc16(inner_packet[:-4])} != {int.from_bytes(checksum, "big")}')

            payload_buffer = BytesIO(payload)
            rest = buffer.read()

            grouped_command_type = int.from_bytes(payload_buffer.read(1), 'little')
            grouped_command_count = int.from_bytes(payload_buffer.read(1), 'little')

            commands = []

            if grouped_command_type == 0xf1:
                for i in range(grouped_command_count):
                    subcommand = int.from_bytes(payload_buffer.read(1), 'little')
                    endpoint_id = int.from_bytes(payload_buffer.read(1), 'little')

                    # XXX: no peeking
                    next_byte = payload_buffer.read(1)
                    payload_buffer.seek(-1, 1)

                    if not next_byte or next_byte in bytearray([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5]):
                        commands.append(('WRITE_ACK', subcommand, endpoint_id))
                        continue

                    command_response_size = int.from_bytes(payload_buffer.read(1), 'little')
                    command_response = payload_buffer.read(command_response_size)

                    if len(command_response) != command_response_size:
                        print(f'????????????????? {pretty_bytes(payload)}')

                    if command_response_size == 0:
                        commands.append(('?????', subcommand, endpoint_id))
                    else:
                        commands.append(('WRITE', subcommand, endpoint_id, command_response))

            if rest:
                raise BadPacketError(f'Unread data remains at end {pretty_bytes(rest)}')

            if 3 + len(payload) + 2 + 2 != total_packet_length:
                raise BadPacketError(f'Invalid packet length {3 + len(payload) + 2 + 2} != {total_packet_length}')


            print(f'{source_addr:02x} --> {dest_addr:02x}  [HASH: {pretty_bytes(checksum)}]')
            
            for command in commands:
                print('    ', command[0], '  command', pretty_bytes([command[1]]), '  endpoint', pretty_bytes([command[2]]), '  payload', command[3:])

            print()
        except BadPacketError as e:
            print(f'Failed to read the packet: {e}')
