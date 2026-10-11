#!/bin/sh
# Rebuild cold_split.elf (stripped, fixed addresses) from cold_split.s.
# Needs clang with the x86_64-linux-gnu target and ld.lld.
set -eu
cd "$(dirname "$0")"
clang --target=x86_64-linux-gnu -c cold_split.s -o cold_split.o
ld.lld -e _start --eh-frame-hdr --strip-all -z norelro \
    --image-base=0x400000 -o cold_split.elf cold_split.o
rm -f cold_split.o
