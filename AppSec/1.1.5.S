.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here

movl $0xb, %eax
push $0x0068732f
push $0x6e69622f
movl %esp, %ebx
movl $0x0, %ecx
movl $0x0, %edx
movl $0x0, %esi
movl $0x0, %edi
push %ebp
movl $0x0, %ebp
int $0x80

pop %ebp

leave
ret
