// Original deterministic AArch64 fixture. Never executed by the tests.
// Explicit instruction words let tests construct linked containers without a
// cross compiler. Labels use byte offsets relative to fixture_entry.
.text
.balign 4
.global fixture_entry
fixture_entry:
.inst 0xa9bf7bfd // stp x29, x30, [sp, #-16]!
.inst 0x910003fd // mov x29, sp
.inst 0x9400000a // bl fixture_sum (offset 48)
.inst 0xa8c17bfd // ldp x29, x30, [sp], #16
.inst 0x34000080 // cbz w0, zero (offset 32)
.inst 0x11000c00 // add w0, w0, #3
.inst 0xd65f03c0 // ret
.inst 0xd503201f // nop (unreachable padding)
zero:
.inst 0x528000e0 // mov w0, #7
.inst 0xd65f03c0 // ret
.inst 0xd503201f // nop
.inst 0xd503201f // nop
.global fixture_sum
fixture_sum:
.inst 0x52800001 // mov w1, #0
.inst 0x34000080 // cbz w0, done (offset 68)
loop:
.inst 0x0b000021 // add w1, w1, w0
.inst 0x71000400 // subs w0, w0, #1
.inst 0x54ffffc1 // b.ne loop (offset 56)
done:
.inst 0x2a0103e0 // mov w0, w1
.inst 0xd65f03c0 // ret
.global fixture_indirect
fixture_indirect:
.inst 0xd61f0040 // br x2
.global fixture_indirect_call
fixture_indirect_call:
.inst 0xd63f0040 // blr x2
.inst 0xd65f03c0 // ret
