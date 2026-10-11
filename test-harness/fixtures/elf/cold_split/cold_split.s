# Control-flow exits that a linear function window misses (rebuild: ./build.sh).
#
# check:    GCC-style hot/cold split. The unlikely path lives in check.cold,
#           placed below check (where GCC's .text.unlikely lands), with its
#           own FDE that starts inside check's frame (CFA=RSP+16, RBX saved).
#           The binary is stripped, so discovery lists check.cold as a
#           function of its own.
# dispatch: PIC jump-table switch whose successors need table recovery.
# fatal:    noreturn helper called from the cold part.

    .intel_syntax noprefix

    .text
    .type check.cold,@function
check.cold:
    .cfi_startproc
    .cfi_def_cfa_offset 16
    .cfi_offset rbx, -16
    lea rdi, [rip + negative_msg]
    call fatal
    .cfi_endproc

    .globl _start
    .type _start,@function
_start:
    .cfi_startproc
    sub rsp, 8
    .cfi_def_cfa_offset 16
    mov edi, 1
    call check
    mov edi, eax
    call dispatch
    add rsp, 8
    .cfi_def_cfa_offset 8
    ret
    .cfi_endproc

    .globl check
    .type check,@function
check:
    .cfi_startproc
    push rbx
    .cfi_def_cfa_offset 16
    .cfi_offset rbx, -16
    mov ebx, edi
    test edi, edi
    js check.cold
    lea eax, [rbx + 1]
    pop rbx
    .cfi_def_cfa_offset 8
    ret
    .cfi_endproc

    .globl dispatch
    .type dispatch,@function
dispatch:
    .cfi_startproc
    cmp edi, 2
    ja .Ldefault
    mov eax, edi
    lea rdx, [rip + .Ltable]
    movsxd rax, dword ptr [rdx + rax*4]
    add rax, rdx
    jmp rax
.Lcase0:
    mov eax, 10
    ret
.Lcase1:
    mov eax, 20
    ret
.Ldefault:
    xor eax, eax
    ret
    .cfi_endproc

    .globl fatal
    .type fatal,@function
fatal:
    .cfi_startproc
    ud2
    .cfi_endproc

    .section .rodata
    .p2align 2
.Ltable:
    .long .Lcase0 - .Ltable
    .long .Lcase1 - .Ltable
    .long .Ldefault - .Ltable
negative_msg:
    .asciz "negative input"
