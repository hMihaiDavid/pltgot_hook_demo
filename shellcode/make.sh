#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage: ./make.sh <shellcode.S>"
	exit -1
fi

as --64 -o tmp.o $1
objcopy -O binary --only-section .text tmp.o sc.bin
rm tmp.o

echo "Shellcode outputed in sc.bin"
