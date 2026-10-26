//! Original symbol-name fixture. Compiled to an object file, never executed.
#![no_std]

pub fn demangle_probe(value: u64) -> u64 {
    value.rotate_left(3)
}

pub fn café(value: u64) -> u64 {
    value.wrapping_add(1)
}
