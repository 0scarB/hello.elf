#!/bin/sh

nasm -f elf64 hello.asm -o hello.o
ld --strip-all -nostdlib hello.o -o hello.elf

