// Original data-reference fixture. Analyzed, never executed. The containers
// place this code at a page-aligned base.
.text
.balign 4
fixture_data:
.inst 0x58000100 // ldr x0, literal (at function+32): instruction-local 8-byte read
.inst 0x100000e2 // adr x2, literal: address taken, no read
.inst 0x90000003 // adrp x3, current page: an incomplete page base
.inst 0x91008063 // add x3, x3, #32: x3 = literal, address taken here
.inst 0xf9400064 // ldr x4, [x3]: propagated 8-byte read of literal
.inst 0x94000002 // bl function+28: the call clobbers x3
.inst 0xf9400065 // ldr x5, [x3]: unresolved after the call
.inst 0xd65f03c0 // ret
.balign 32
literal:
.quad 0x2166657261746164 // little-endian bytes: dataref!
