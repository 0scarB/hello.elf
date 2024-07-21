#!/bin/python3

# MIT licensed. Full license at end of file.

import os
import sys


def gen_msg_elf(file_path: str, msg: str, *, hacks: bool):
    BASE_MEM_ADDRESS = 0x400000

    header_size                         = -1
    prog_entry_offset                   = -1
    prog_header_table_offset            = -1
    x86_64_next_instructions_jmp_offset = -1
    msg_address                         = -1
    x86_64_instructions                 = []
    bytes_                              = []
    do_relocate_msg_hack                = hacks

    def add_n_byte_num(n_bytes: int, num: int):
        for _ in range(n_bytes):
            bytes_.append(num & 0xFF)
            num >>= 8

    PASSES = 2
    for _ in range(PASSES):
        bytes_.clear()

        #
        # ELF Header
        #

        # Add ELF magic number
        bytes_ += [0x7F, ord('E'), ord('L'), ord('F')]

        FORMAT_64_BIT = 2
        bytes_.append(FORMAT_64_BIT)

        LITTLE_ENDIAN = 1
        bytes_.append(LITTLE_ENDIAN)

        ELF_VERSION_ORIG = 1
        bytes_.append(ELF_VERSION_ORIG)

        ABI_SYSTEM_V = 0
        bytes_.append(ABI_SYSTEM_V)

        # Hack: Put the last 8 x86-64 instructions in the ELF Header's abi version
        #       field and padding
        abi_version_bytes_n = 1
        padding_bytes_n     = 7
        if hacks:
            x86_64_next_instructions_jmp_offset = len(bytes_)
            x86_64_instructions_end = [
                0xb2, len(msg), # mov  dl, <msg length>
                0x0f, 0x05,     # syscall

                0xb0, 0x01,     # mov  al, 1
                0xcd, 0x80,     # int 0x80
            ]
            assert len(x86_64_instructions_end) == abi_version_bytes_n + padding_bytes_n
            bytes_ += x86_64_instructions_end
        else:
            ABI_VERSION_UNSPECIFIED = 0
            bytes_.append(ABI_VERSION_UNSPECIFIED)

            add_n_byte_num(padding_bytes_n, 0)

        EXECUTABLE_FILE_TYPE = 2
        add_n_byte_num(2, EXECUTABLE_FILE_TYPE)

        ARCH_AMD_X86_64 = 0x3E
        add_n_byte_num(2, ARCH_AMD_X86_64)

        ELF_VERSION_ORIG = 1
        add_n_byte_num(4, ELF_VERSION_ORIG)

        add_n_byte_num(8, BASE_MEM_ADDRESS + prog_entry_offset)

        add_n_byte_num(8, prog_header_table_offset)

        # Hack: Use the fields for a) the section table offset, b) the machine
        #       flags and c) the header size as a region to store the message
        #       instead of their intented uses.
        if do_relocate_msg_hack:
            msg_address = BASE_MEM_ADDRESS + len(bytes_)

            FIELD_SIZE_PROG_SECTION_TABLE_OFFSET = 8
            FIELD_SIZE_MACHINE_FLAGS             = 4
            FIELD_SIZE_HEADER_SIZE               = 2
            msg_region_size = FIELD_SIZE_PROG_SECTION_TABLE_OFFSET + \
                              FIELD_SIZE_MACHINE_FLAGS             + \
                              FIELD_SIZE_HEADER_SIZE

            if len(msg) <= msg_region_size:
                for char in msg:
                    bytes_.append(ord(char))
                bytes_ += [0]*(msg_region_size - len(msg))
            else:
                do_relocate_msg_hack = False
        if not do_relocate_msg_hack:
            PROG_SECTION_TABLE_OFFSET_UNSPECIFIED = 0
            add_n_byte_num(8, PROG_SECTION_TABLE_OFFSET_UNSPECIFIED)

            machine_flags = 0
            add_n_byte_num(4, machine_flags)

            add_n_byte_num(2, header_size)

        PROG_HEADER_TABLE_ENTRY_SIZE_64_BIT = 56
        add_n_byte_num(2, PROG_HEADER_TABLE_ENTRY_SIZE_64_BIT)

        # Hack: Omit unused trailing fields in ELF Header and overlap with
        #       the ELF Program Table
        if not hacks:
            prog_header_table_entries_n = 1
            add_n_byte_num(2, prog_header_table_entries_n)

            PROG_SECTION_TABLE_ENTRY_SIZE_64_BIT = 64
            add_n_byte_num(2, PROG_SECTION_TABLE_ENTRY_SIZE_64_BIT)

            # Add the number of entries in the program section table
            prog_section_table_entries_n = 0
            add_n_byte_num(2, prog_section_table_entries_n)

            section_table_names_entry_idx = 0
            add_n_byte_num(2, section_table_names_entry_idx)

        header_size = len(bytes_)

        #
        # ELF Program Table
        #

        prog_header_table_offset = len(bytes_)

        ENTRY_TYPE_LOAD = 1
        add_n_byte_num(4, ENTRY_TYPE_LOAD)

        EXECUTABLE = 1
        READABLE   = 4
        flags      = EXECUTABLE | READABLE
        add_n_byte_num(4, flags)

        offset_in_file = prog_entry_offset
        add_n_byte_num(8, offset_in_file)

        virtual_mem_address = BASE_MEM_ADDRESS + prog_entry_offset
        add_n_byte_num(8, virtual_mem_address)

        # Hack: Put initial x86-64 instructions inside fields for the segments
        #       physical size and file size.
        #       The physical size is ignored so that's fine.
        #       The file size needs to be greater than the number of initial
        #       x86-64 instructions (8) which is true this and most cases.
        physical_mem_address_bytes_n = 8
        segment_size_in_file_bytes_n = 8
        if hacks:
            prog_entry_offset = len(bytes_)

            x86_64_instructions = [
                0xb0, 0x01,                   # mov  al,1
                0x40, 0x88, 0xc7,             # mov  al, dil
                0xbe,                         # mov esi, <msg_address>
                    (msg_address>> 0) & 0xFF, #                .
                    (msg_address>> 8) & 0xFF, #                .
                    (msg_address>>16) & 0xFF, #                .
                    (msg_address>>24) & 0xFF, #                .

                0xeb, -1                    # jmp <next instructions>
            ]
            bytes_ += x86_64_instructions

            jmp_dist = len(bytes_) - x86_64_next_instructions_jmp_offset
            jmp_dist = (~jmp_dist    ) & 0xFF
            jmp_dist = ( jmp_dist + 1) & 0xFF
            bytes_[-1] = jmp_dist

            bytes_ += [0]*(
                physical_mem_address_bytes_n + segment_size_in_file_bytes_n
                - len(x86_64_instructions))
        else:
            physical_mem_address = BASE_MEM_ADDRESS + prog_entry_offset
            add_n_byte_num(physical_mem_address_bytes_n, physical_mem_address)

            segment_size_in_file = len(x86_64_instructions)
            add_n_byte_num(segment_size_in_file_bytes_n, segment_size_in_file)

        # Set the segment memory size as a duplicate of the segment file size
        segment_size_in_file_bytes = bytes_[-8:]
        segment_size_in_mem_bytes  = segment_size_in_file_bytes
        bytes_ += segment_size_in_mem_bytes

        NO_ALIGNMENT = 0
        add_n_byte_num(8, NO_ALIGNMENT)

        #
        # Bytes after headers
        #

        if not hacks:
            prog_entry_offset = len(bytes_)

            x86_64_instructions = [
                0xb0, 0x01,                   # mov  al,1
                0x40, 0x88, 0xc7,             # mov  al, dil
                0xbe,                         # mov esi, <msg_address>
                    (msg_address>> 0) & 0xFF, #                .
                    (msg_address>> 8) & 0xFF, #                .
                    (msg_address>>16) & 0xFF, #                .
                    (msg_address>>24) & 0xFF, #                .
                0xb2, len(msg),               # mov  dl, <msg length>
                0x0f, 0x05,                   # syscall

                0xb0, 0x01,                   # mov  al, 1
                0xcd, 0x80,                   # int 0x80
            ]
            bytes_ += x86_64_instructions

        if not do_relocate_msg_hack:
            msg_address = BASE_MEM_ADDRESS + len(bytes_)
            for char in msg:
                bytes_.append(ord(char))
                x86_64_instructions.append(ord(char))

    with open(file_path, 'wb') as f:
        f.write(bytes(bytes_))
    os.chmod(file_path, 0o740)

    print("Generated: " + file_path.ljust(20)                  +
          " Hacks enabled: " + ("Yes  " if hacks else "No   ") +
          " Size in bytes: " + str(len(bytes_))              )


def main():
    HACKS_ON_BY_DEFAULT = True

    def print_usage():
        print(
            sys.argv[0] + " FILE_PATH MSG [--hacks/--no-hacks|-h|--help]\n"
            "\n"
            "Generate a small x86-64, Linux ELF executable that will print\n"
            "a message of your choice when exected.\n"
            "\n"
            "FILE_PATH           Path to the generated ELF file.\n"
            "MSG                 The message that will be printed.\n"
            "--hacks/--no-hacks  While generating, use hacks that will\n"
            "                    intentionally corrupt the ELF file to\n"
            "                    reduce size. Default: " +
                ("--hacks" if HACKS_ON_BY_DEFAULT else "--no-hacks") + "\n"
            "                    (Corrupting will not prevent the ELF file\n"
            "                    from being executed.)\n"
            "-h|--help           Print this usage message.\n"
        )

    if "-h" in sys.argv or "--help" in sys.argv:
        print_usage()
        exit(0)

    hacks = HACKS_ON_BY_DEFAULT
    while "--hacks" in sys.argv or "--no-hacks" in sys.argv:
        try:
            arg_idx = sys.argv.index("--hacks")
        except ValueError:
            arg_idx = sys.argv.index("--no-hacks")
        arg = sys.argv.pop(arg_idx)
        if arg == "--hacks":
            hacks = True
        else:
            hacks = False

    n_args = len(sys.argv) - 1
    if n_args != 2:
        print("ERROR (" + sys.argv[0] + "): Got " + str(n_args) + " arguments, "
              "instead of the 2 expected arguments 'FILE_PATH' and 'MSG'!",
              file=sys.stderr)
        print("\nUSAGE: ", end="")
        print_usage()
        exit(1)

    file_path = sys.argv[1]
    msg       = sys.argv[2]

    gen_msg_elf(file_path, msg, hacks=hacks)


if __name__ == "__main__":
    main()

# Copyright 2024 Oscar Butler-Aldridge
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

