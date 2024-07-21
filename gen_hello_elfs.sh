#!/bin/sh
set -eu

msg='Hello, World!
'
./gen_msg_elf.py 'hello.elf'          "$msg" --hacks
./gen_msg_elf.py 'hello-no-hacks.elf' "$msg" --no-hacks

