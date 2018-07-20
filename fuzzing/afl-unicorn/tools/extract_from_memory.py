"""

    Extract the data contained in a buffer and save to file

    Usefull to create a input file for afl-unicorn

    2018 Giulio Ginesi

"""

import gdb
import zlib
import datetime
import time

BUFFER_ADDR = 0x76c6a008
BUFFER_LEN  = 0x200ee

try:
    buffer = read_memory(BUFFER_ADDR, BUFFER_LEN)
    print("Dumping buffer from 0x{0:x} of length 0x{1:x}".format(BUFFER_ADDR, BUFFER_LEN))
except:
    print("Error reading memory region!")

#compressed_buffer = zlib.compress(buffer)

timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
try:
    out_name = 'input_'+timestamp+'.bin'
    out_file = open(out_name, 'wb')
    out_file.write(buffer)
    out_file.close()
    print("Saved file with name {}".format(out_name))
except:
    print("Error saving file!")
