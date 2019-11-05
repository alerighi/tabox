use std::fs;
use std::str;
use std::process::Command;
use std::sync::Once;

use crate::{SandboxConfiguration, SandboxConfigurationBuilder, SandboxExecutionResult, SandboxImplementation, Sandbox};
use std::path::PathBuf;

struct ExecutionResult {
    result: SandboxExecutionResult,
    stdout: String,
    stderr: String,
}

fn exec(program: &str, config: &mut SandboxConfigurationBuilder, stdin: &str) -> ExecutionResult {
    let temp = tempdir::TempDir::new("temp").unwrap();

    let source_path = temp.path().join("program.c");
    fs::write(&source_path, program).unwrap();

    let executable_path = temp.path().join("program");
    let compile_output = Command::new("gcc")
        .args(&["-o", executable_path.to_str().unwrap(), source_path.to_str().unwrap()])
        .output()
        .unwrap();

    eprintln!("Compiler stdout: {}", str::from_utf8(&compile_output.stdout).unwrap());
    eprintln!("Compiler stderr: {}", str::from_utf8(&compile_output.stderr).unwrap());

    assert!(compile_output.status.success(), "Compilation error");

    config.mount_paths(vec![
        PathBuf::from("/usr"),
        PathBuf::from("/lib64"),
        PathBuf::from(temp.path()),
    ]);
    config.working_directory(PathBuf::from(temp.path()));
    config.executable(executable_path);
    config.stdin(temp.path().join("stdin.txt"));
    config.stdout(temp.path().join("stdout.txt"));
    config.stderr(temp.path().join("stderr.txt"));

    let config = config.build().unwrap();

    fs::write(config.stdin.as_ref().unwrap(), stdin).unwrap();

    let sandbox = SandboxImplementation::run(config.clone()).unwrap();
    let result = sandbox.wait().unwrap();

    ExecutionResult {
        result,
        stdout: fs::read_to_string(&config.stdout.unwrap()).unwrap(),
        stderr: fs::read_to_string(&config.stderr.unwrap()).unwrap(),
    }
}

#[test]
fn test_ok_program() {
    let program = r#"
       #include <stdio.h>
       int main() { printf("hello, world!"); fprintf(stderr, "error"); return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.time_limit(1);
    config.memory_limit(256);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.return_code, Some(0));
    assert_eq!(result.result.signal, None);
    assert_eq!(result.stdout, "hello, world!");
    assert_eq!(result.stderr, "error");
}

#[test]
fn test_signal_program() {
    let program = r#"
       #include <stdio.h>
       int main() { int *ptr = NULL; *ptr = 42; return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.return_code, None);
    assert_eq!(result.result.signal, Some(11));
}

#[test]
fn test_time_limit() {
    let program = r#"
       #include <stdio.h>
       int main() { while(1); }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.time_limit(1);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.return_code, None);
    assert_eq!(result.result.signal, Some(9));

}

#[test]
fn test_memory_limit_exceeded() {
    let program = r#"
       #include <stdlib.h>
       int main() { int s = 256 * 1000000; char *m = malloc(s); for (int i = 0; i < s; i++) m[i] = i; return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.memory_limit(256);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.return_code, None);
    assert_eq!(result.result.signal, Some(11));
}

#[test]
fn test_memory_limit_ok() {
    let program = r#"
       #include <stdlib.h>
       int main() { int s = 200 * 1000000; char *m = malloc(s); for (int i = 0; i < s; i++) m[i] = i; return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.memory_limit(256);

    let result = exec(program, &mut config, "");

    assert!(result.result.resource_usage.memory_usage > 200_000_000);
    assert_eq!(result.result.return_code, Some(0));
    assert_eq!(result.result.signal, None);
}

#[test]
fn test_seccomp_filter() {
    let program = r#"
       #include <unistd.h>
       int main() { getuid(); return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.memory_limit(256);
    config.syscall_filter(vec!["getuid".to_string()]);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.return_code, None);
    assert_eq!(result.result.signal, Some(31));
}
