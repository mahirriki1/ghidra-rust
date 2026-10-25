/* Original pointer recovery fixture; built for analysis, never executed. */
.macro begin name
.globl \name
.type \name,@function
\name:
#ifndef NO_UNWIND
.cfi_startproc
#endif
.endm
.macro end name
#ifndef NO_UNWIND
.cfi_endproc
#endif
.size \name,.-\name
.endm
.text
begin _start
xor %eax,%eax
ret
end _start
.p2align 4
begin pointer_a
imul $7,%edi,%eax
ret
end pointer_a
.p2align 4
begin pointer_b
imul $13,%edi,%eax
ret
end pointer_b
.p2align 4
begin singleton
imul $19,%edi,%eax
ret
end singleton
.p2align 4
begin label_owner
xor %eax,%eax
.globl computed_label_a
computed_label_a:
add $1,%eax
.globl computed_label_b
computed_label_b:
add $2,%eax
ret
end label_owner

/* Format-defined single callbacks need no unwind or prologue evidence. */
.p2align 4
.globl init_callback
.type init_callback,@function
init_callback:
endbr64
#ifndef NO_UNWIND
jmp crt_forward_target
#else
.byte 0xe9
.long crt_forward_target - . - 4
#endif
.size init_callback,.-init_callback
.globl crt_forward_target
.type crt_forward_target,@function
crt_forward_target:
ret
.size crt_forward_target,.-crt_forward_target
.globl fini_callback
.type fini_callback,@function
fini_callback:
ret
.size fini_callback,.-fini_callback
.section .init,"ax",@progbits
.globl _init
.type _init,@function
_init:
ret
.size _init,.-_init
.section .fini,"ax",@progbits
.globl _fini
.type _fini,@function
_fini:
ret
.size _fini,.-_fini
.section .init_array,"aw",@init_array
.p2align 3
.quad init_callback
.section .fini_array,"aw",@fini_array
.p2align 3
.quad fini_callback

.section .data.rel.ro,"aw",@progbits
.p2align 3
/* Cross a source scan boundary and a candidate-validation boundary. */
.zero 1048064
.globl valid_table
valid_table:
.rept 128
.quad pointer_a
.endr
.quad pointer_b
.quad 0
/* One distinct target, offcuts, internal labels, and mixed code/data. */
.quad singleton,singleton,0
.quad pointer_a+1,pointer_b+1,0
.quad computed_label_a,computed_label_b,0
.quad singleton,valid_table,pointer_a,0
.section .note.GNU-stack,"",@progbits
