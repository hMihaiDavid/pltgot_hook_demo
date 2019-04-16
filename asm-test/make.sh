#!/bin/bash
as --64 -o sc.o $1
ld -Ttext 200000 --oformat binary -o sc.bin sc.o
