.section .text
.globl _start

_ret:  # space for the return address
	.rept 8
	.byte 0x00
	.endr
_start:
	pushq -14(%rip) # push return address 

	# Write payload here!
	# It is payload writer's responsibility to not corrupt the stack
	# nor register values unles desired.
	##########################################

	# crappy PIC data section.
	# don't use .section .data cause only .text is outputed to sc.bin
	call _end_data
	data:
		.ascii "Holaaaaaaaaaaa\n\0"
	_end_data:
	# now address of data is on top of stack :) 
		
	# rdi holds first parameter (string to print). Overwrite it with our string.
	popq %rdi

	##########################################
	ret
