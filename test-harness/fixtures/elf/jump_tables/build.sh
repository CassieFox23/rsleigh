#!/bin/sh
# Rebuild jump_tables.elf (stripped, fixed addresses) from jump_tables.s.
# Needs clang with the x86_64-linux-gnu target and ld.lld.
set -eu
cd "$(dirname "$0")"
clang --target=x86_64-linux-gnu -c jump_tables.s -o jump_tables.o
ld.lld -e _start --eh-frame-hdr --strip-all -z norelro \
    --image-base=0x400000 -o jump_tables.elf jump_tables.o
rm -f jump_tables.o
