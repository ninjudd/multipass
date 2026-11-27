//! Checks on what the built program loads when it starts.

#![cfg(target_os = "macos")]

use std::process::Command;

/// AppKit is loaded only by `--clip`, so a command that never touches the
/// clipboard must run without it in the process.
#[test]
fn commands_without_clip_do_not_load_appkit() {
    let output = Command::new(env!("CARGO_BIN_EXE_multipass"))
        .arg("--version")
        .env("DYLD_PRINT_LIBRARIES", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let loaded = String::from_utf8_lossy(&output.stderr);
    assert!(
        loaded.contains("libSystem"),
        "dyld did not list the loaded images:\n{loaded}"
    );
    assert!(
        !loaded.contains("AppKit.framework"),
        "AppKit was loaded:\n{loaded}"
    );
}
