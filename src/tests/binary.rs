use crate::result::ExitStatus;
use crate::tests::util::ExecutionResult;
use std::path::Path;
use std::process::{Command, Output};

/// Execute compiled program
fn run_program(args: Vec<&str>) -> Output {
    let exe = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/tabox");
    Command::new(exe)
        .args(args)
        .output()
        .expect("Error spawning process")
}

/// Run a command in bash
fn run_shell(command: &str) -> ExecutionResult {
    let mut args = Vec::new();
    args.push("--json");
    args.push("--allow-insecure");
    args.push("--env");
    args.push("PATH");
    args.push("--mount");
    args.push("/usr");
    args.push("/bin");
    args.push("/sbin");
    args.push("/lib64");
    args.push("/lib");
    args.push("/etc");
    args.push("/var");
    args.push("--mount-tmpfs");
    args.push("--working-directory");
    args.push("/tmp");
    args.push("--allow-multiprocess");
    args.push("--");
    args.push("/bin/bash");
    args.push("-c");
    args.push(command);

    let output = run_program(args);
    assert!(output.status.success());

    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::str::from_utf8(&output.stderr).unwrap();

    eprintln!("stdout = {}", stdout);
    eprintln!("stderr = {}", stderr);

    ExecutionResult {
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        result: serde_json::from_str(stderr).unwrap(),
    }
}

/// Test running bash
#[test]
fn test_echo() {
    let output = run_shell("echo -n Hello, world!");
    assert_eq!(output.stdout, "Hello, world!");
}

/// Test no ping
#[cfg(target_os = "linux")]
#[test]
fn test_ping() {
    let output = run_shell("ping 8.8.8.8 2>&1");
    assert!(!output.result.status.success());
    assert_eq!(output.result.status, ExitStatus::ExitCode(2));
}

/// Test no curl
#[cfg(target_os = "linux")]
#[test]
fn test_curl() {
    let output = run_shell("curl 8.8.8.8 2>&1");
    assert!(!output.result.status.success());
    assert_eq!(output.result.status, ExitStatus::ExitCode(7));
}

/// Test blocking chmod
#[cfg(target_os = "linux")]
#[test]
fn test_chmod() {
    let output = run_shell("bash -c 'touch file; chmod 777 file' 2>&1");
    assert!(!output.result.status.success());
}
