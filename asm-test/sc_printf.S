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
	########################################

	# crappy PIC data section.
	call _end_data
	data:
		.ascii "Holaaaaaaaaaaa\n\0"
	_end_data:
	# now address of data is on top of stack :) 
		
	# rdi holds pointer to format string. Overwrite it with our string.
	popq %rdi

	##########################################
	ret
	
	# resulting bin size must be multiple of 8
	nop
	nop
	nop


