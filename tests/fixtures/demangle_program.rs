//! Original linked symbol-name fixture. Analyzed by tests, never executed.
//! Without std it has no thread-local sections, which the loader rejects when
//! they overlap other mapped sections. Windows builds it as a dylib so its
//! Rust functions are exported by name.
#![no_std]
#![no_main]

#[inline(never)]
pub fn demangle_probe(value: u64) -> u64 {
    core::hint::black_box(value).rotate_left(3)
}

#[inline(never)]
pub fn café(value: u64) -> u64 {
    core::hint::black_box(value).wrapping_add(1)
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    let value = core::hint::black_box(7);
    (demangle_probe(value) ^ café(value)) as i32
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
