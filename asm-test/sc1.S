.section .text
.globl _start
_start:
	_ret:  # space for the return address
	.byte 0x00
	.byte 0x00
	.byte 0x00
	.byte 0x00
	.byte 0x00
	.byte 0x00
	.byte 0x00
	.byte 0x00

	pushq -14(%rip) # push return address 

	# Write payload here!
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

	ret
