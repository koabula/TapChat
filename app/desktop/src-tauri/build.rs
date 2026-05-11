fn main() {
    println!("cargo:rustc-check-cfg=cfg(mobile)");

    let test_support = std::env::var_os("CARGO_FEATURE_TEST_SUPPORT").is_some();
    let gui = std::env::var_os("CARGO_FEATURE_GUI").is_some();
    if test_support && !gui {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // Ensure plugins configuration is properly embedded.
    tauri_build::build()
}
