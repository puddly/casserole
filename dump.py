import sys
import serial

with serial.Serial(sys.argv[1], baudrate=115200) as ser:
    line_count = 0

    while True:
        print(f'{ord(ser.read(1)):02x} ', end='', flush=True)
        line_count += 1

        if line_count == 32:
            line_count = 0
            print('')
