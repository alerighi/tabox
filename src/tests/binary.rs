#[cfg(target_os = "linux")]
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
#[allow(clippy::vec_init_then_push)]
fn run_shell(command: &str) -> ExecutionResult {
    let stderr_dir = tempfile::TempDir::new().unwrap();
    let stderr_file = stderr_dir.path().join("stderr.txt");

    let mut args = Vec::new();
    args.push("--json");
    args.push("--allow-insecure");
    args.push("--env");
    args.push("PATH");
    args.push("--mount");
    args.push("/usr");
    args.push("/bin");
    args.push("/sbin");
    args.push("/lib");
    args.push("/etc");
    args.push("/var");

    if Path::new("/lib64").exists() {
        args.push("/lib64");
    }

    args.push("--mount-tmpfs");
    args.push("--working-directory");
    args.push("/tmp");
    args.push("--allow-multiprocess");
    args.push("--stderr");
    args.push(stderr_file.to_str().unwrap());
    args.push("--");
    args.push("/bin/bash");
    args.push("-c");
    args.push(command);

    let output = run_program(args);
    assert!(output.status.success());

    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let stderr = std::fs::read_to_string(&stderr_file).unwrap_or_default();
    let result = std::str::from_utf8(&output.stderr).unwrap();

    eprintln!("stdout = {}", stdout);
    eprintln!("stderr = {}", stderr);
    eprintln!("result = {}", result);

    ExecutionResult {
        stdout: stdout.to_owned(),
        stderr,
        result: serde_json::from_str(result).unwrap(),
    }
}

/// Test running bash
#[test]
fn test_echo() {
    let output = run_shell("exec echo -n Hello, world!");
    assert_eq!(output.stdout, "Hello, world!");
}

/// Test no ping
#[cfg(target_os = "linux")]
#[test]
fn test_ping() {
    let output = run_shell("exec ping 8.8.8.8");
    assert!(!output.result.status.success());
    assert_eq!(output.result.status, ExitStatus::ExitCode(2));
}

/// Test no curl
#[cfg(target_os = "linux")]
#[test]
fn test_curl() {
    let output = run_shell("exec curl 8.8.8.8");
    assert!(!output.result.status.success());
    assert_eq!(output.result.status, ExitStatus::ExitCode(7));
}

/// Test blocking chmod
#[cfg(target_os = "linux")]
#[test]
fn test_chmod() {
    let output = run_shell("touch file; exec chmod 777 file");
    assert!(!output.result.status.success());
    assert_eq!(
        output.result.status.signal_name().unwrap(),
        "Bad system call"
    );
}
