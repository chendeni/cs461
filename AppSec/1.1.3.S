.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here


push $0xc001f00d
movl %esp, %eax
push %eax
push $0xc105ed
push $0xacce55ed
call practice
add $0x16, %esp


leave
ret

//.data	

//cool_food:
//	.long 0xc001f00d
