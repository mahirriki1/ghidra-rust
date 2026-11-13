//! Trusted test worker which never replies. Compiled privately by headless tests.
fn main() {
    use std::io::BufRead;
    let _ = std::io::stdin().lock().lines().next();
    std::thread::sleep(std::time::Duration::from_secs(60));
}
