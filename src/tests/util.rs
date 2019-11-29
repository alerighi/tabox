use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::str;

use crate::{
    BindMount, DirectoryMount, Sandbox, SandboxConfigurationBuilder, SandboxExecutionResult,
    SandboxImplementation,
};

pub struct ExecutionResult {
    pub result: SandboxExecutionResult,
    pub stdout: String,
    pub stderr: String,
}

pub fn exec(
    program: &str,
    config: &mut SandboxConfigurationBuilder,
    stdin: &str,
) -> ExecutionResult {
    let temp = tempdir::TempDir::new("temp").unwrap();

    let source_path = temp.path().join("program.c");
    fs::write(&source_path, program).unwrap();

    let executable_path = temp.path().join("program");
    let compile_output = Command::new("gcc")
        .args(&[
            "-o",
            executable_path.to_str().unwrap(),
            source_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    eprintln!(
        "Compiler stdout: {}",
        str::from_utf8(&compile_output.stdout).unwrap()
    );
    eprintln!(
        "Compiler stderr: {}",
        str::from_utf8(&compile_output.stderr).unwrap()
    );

    assert!(compile_output.status.success(), "Compilation error");

    config.mount_paths(vec![
        DirectoryMount::Bind(BindMount {
            source: PathBuf::from("/usr"),
            target: PathBuf::from("/usr"),
            writable: false,
        }),
        DirectoryMount::Bind(BindMount {
            source: PathBuf::from("/lib64"),
            target: PathBuf::from("/lib64"),
            writable: false,
        }),
        DirectoryMount::Bind(BindMount {
            source: temp.path().to_owned(),
            target: temp.path().to_owned(),
            writable: true,
        }),
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
