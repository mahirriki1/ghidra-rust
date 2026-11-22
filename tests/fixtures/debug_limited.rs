use std::hint::black_box;

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn scaled_counter() -> i32 {
    black_box(4_i32).wrapping_mul(3).wrapping_add(1)
}

fn main() {
    black_box(scaled_counter());
}
