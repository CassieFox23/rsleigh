# Jump tables the recovery used to miss (rebuild: ./build.sh).
#
# far_base:   the table base is set 20 instructions before the jump.
# wide_table: a 300-entry table.
# offset_index: the index is built by `add`, and the table load overwrites it.

    .intel_syntax noprefix

    .text
    .globl _start
    .type _start,@function
_start:
    .cfi_startproc
    sub rsp, 8
    .cfi_def_cfa_offset 16
    mov edi, 1
    call far_base
    call wide_table
    call offset_index
    add rsp, 8
    .cfi_def_cfa_offset 8
    ret
    .cfi_endproc

    .globl far_base
    .type far_base,@function
far_base:
    .cfi_startproc
    lea rdx, [rip + .Lfar_table]
    .rept 20
    nop
    .endr
    cmp edi, 2
    ja .Lfar_default
    mov eax, edi
    movsxd rax, dword ptr [rdx + rax*4]
    add rax, rdx
    jmp rax
.Lfar_case0:
    mov eax, 30
    ret
.Lfar_case1:
    mov eax, 31
    ret
.Lfar_default:
    xor eax, eax
    ret
    .cfi_endproc

    .globl wide_table
    .type wide_table,@function
wide_table:
    .cfi_startproc
    cmp edi, 299
    ja .Lwide_default
    mov eax, edi
    lea rdx, [rip + .Lwide_table]
    movsxd rax, dword ptr [rdx + rax*4]
    add rax, rdx
    jmp rax
.Lwide_case0:
    mov eax, 50
    ret
.Lwide_case1:
    mov eax, 51
    ret
.Lwide_last:
    mov eax, 52
    ret
.Lwide_default:
    xor eax, eax
    ret
    .cfi_endproc

    .globl offset_index
    .type offset_index,@function
offset_index:
    .cfi_startproc
    add edi, 5
    cmp edi, 2
    ja .Loffset_default
    lea rdx, [rip + .Loffset_table]
    movsxd rdi, dword ptr [rdx + rdi*4]
    add rdi, rdx
    jmp rdi
.Loffset_case0:
    mov eax, 60
    ret
.Loffset_case1:
    mov eax, 61
    ret
.Loffset_default:
    xor eax, eax
    ret
    .cfi_endproc

    .section .rodata
    .p2align 2
.Lfar_table:
    .long .Lfar_case0 - .Lfar_table
    .long .Lfar_case1 - .Lfar_table
    .long .Lfar_default - .Lfar_table
.Lwide_table:
    .long .Lwide_case0 - .Lwide_table
    .long .Lwide_case1 - .Lwide_table
    .rept 297
    .long .Lwide_default - .Lwide_table
    .endr
    .long .Lwide_last - .Lwide_table
.Loffset_table:
    .long .Loffset_case0 - .Loffset_table
    .long .Loffset_case1 - .Loffset_table
    .long .Loffset_default - .Loffset_table
