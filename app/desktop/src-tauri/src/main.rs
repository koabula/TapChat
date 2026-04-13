// Hide console window on Windows release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tapchat_desktop_lib::run();
}
