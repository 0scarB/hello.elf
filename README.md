## hello.elf

`hello.elf` and `hello-no-hacks.elf` are custom-generated ELF executable files
for x86-64, System V compatible -- Linux, FreeBSD, MacOS -- systems. They
print "Hello, World!" when executed.

My goal is to make them pretty small. The current sizes are:

| File                 | Size in bytes |
| -------------------- | ------------- |
| `hello.elf`          | 122           |
| `hello-no-hacks.elf` | 157           |

The ELF files are generated using the [`gen_msg_elf.py`](./gen_msg_elf.py)
script. It generates an ELF executable that prints a message of your choice.
You can run it yourself by supplying a `FILE_PATH` and then `MSG` argument. Run
`./gen_msg_elf.py --help` for more details. The source code of
[`gen_msg_elf.py`](./gen_msg_elf.py) may be educational if you're trying to
generate your own ELF files from scratch. The bit that generates the executable
is around 200 lines of mostly sequential code with added "explainer" variables.

`hello.elf` is generated using hacks that intentionally corrupt the ELF file
but do not prevent it from executing. `hello-no-hacks.elf` does not use these
hacks, producing a fully valid ELF file. The hacks allow `hello.elf` to be
smaller as seen above. Similar and more extensive hacks can be found in this
great article <https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html>
-- It's worth a read if you have the time.

The `asm-reference/` directory contains a reference "Hello, World!"
implementation is NASM.

### Resources and Tools

- Wikipedia on ELF: <https://en.wikipedia.org/wiki/Elf>
- Linux Manpage on ELF: [`man elf`](https://www.man7.org/linux/man-pages/man5/elf.5.html)
- Disassembly tools: `readelf`, `objdump`, `hexdump`

### Why?

To learn more about ELF, Assembly and x86-64 instructions.

### Licensing and Attribution

Treat all code in this repo as [MIT licensed](./LICENSE.txt). Treat other
assets as CC0 / Public Domain.

Attribution by linking to this repo would be appreciated but is not required.

