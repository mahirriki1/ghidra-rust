// Original extra code for ARM64 PE metadata/import regression tests.
// tests/common places these three small routines at .text+0x80, +0x90, +0xa0
// and the import veneer at +0xc0. These bytes are analyzed, never executed.
fixture_metadata_only:
.inst 0x528000e0 // mov w0,#7
.inst 0xd65f03c0 // ret
fixture_fragment:
.inst 0x52800120 // mov w0,#9
.inst 0xd65f03c0 // ret
fixture_import_caller:
.inst 0xa9bf7bfd // stp x29,x30,[sp,#-16]!
.inst 0x910003fd // mov x29,sp
.inst 0x94000006 // bl .text+0xc0 (from +0xa8)
.inst 0xa8c17bfd // ldp x29,x30,[sp],#16
.inst 0xd65f03c0 // ret
fixture_import_veneer:
.inst 0xb0000010 // adrp x16, image+0x2000
.inst 0xf9428211 // ldr x17,[x16,#0x500] (named IAT slot)
.inst 0xd61f0220 // br x17 (runtime target remains unknown)
