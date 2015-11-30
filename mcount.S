#define __ASSEMBLY__

#include "hotpatcher.h"

#define _ALIGN_TEXT .align 16, 0x90

#define ENTRY(x) \
        .text; _ALIGN_TEXT; .globl x; .type x,@function; x:

ENTRY(hpatch_caller)
    push %rbp
    movq %rsp, %rbp
    subq $0x08, %rsp
    movq %rdi, (%rsp)

	call find_hpatch_function
    call *%rax

    movq 8(%rbp), %rdi

    call find_leave_addr
    movq %rax, 8(%rbp)

    movq (%rsp), %rdi
    addq $0x08, %rsp

    leaveq
    retq
