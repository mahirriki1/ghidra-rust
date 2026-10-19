// Original instruction-local data-reference fixture. Analyzed, never executed.
.text
.balign 4
fixture_data:
.inst 0x58000100 // ldr x0, literal (at function+32): direct8-byte read
.inst 0x100000e2 // adr x2, literal: address only, no read
.inst 0x90000003 // adrp x3, current page: no interinstruction propagation
.inst 0xf9400064 // ldr x4,[x3]: unresolved by this instruction-local pass
.inst 0xd65f03c0 // ret
.balign 32
literal:
.quad 0x2166657261746164 // little-endian bytes: dataref!
