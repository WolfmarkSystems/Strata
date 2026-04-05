// Prevents an additional console window on Windows for both debug and release builds.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    forensic_suite_lib::run()
}
