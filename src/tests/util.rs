// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;

use crate::configuration::SandboxConfiguration;
use crate::result::SandboxExecutionResult;
use crate::{Sandbox, SandboxImplementation};

#[derive(Debug)]
pub struct ExecutionResult {
    pub result: SandboxExecutionResult,
    pub stdout: String,
    pub stderr: String,
}

pub fn exec(program: &str, config: &mut SandboxConfiguration, stdin: &str) -> ExecutionResult {
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

    config
        .mount(PathBuf::from("/usr"), PathBuf::from("/usr"), false)
        .mount(PathBuf::from("/lib"), PathBuf::from("/lib"), false)
        .mount(PathBuf::from("/bin"), PathBuf::from("/bin"), false)
        .mount(PathBuf::from("/etc"), PathBuf::from("/etc"), false)
        .mount(temp.path().to_owned(), temp.path().to_owned(), true)
        .mount_tmpfs(true)
        .working_directory(PathBuf::from(temp.path()))
        .executable(executable_path)
        .stdin(temp.path().join("stdin.txt"))
        .stdout(temp.path().join("stdout.txt"))
        .stderr(temp.path().join("stderr.txt"));

    if Path::new("/lib64").exists() {
        config.mount(PathBuf::from("/lib64"), PathBuf::from("/lib64"), false);
    }

    let config = config.clone().build();

    fs::write(config.stdin.as_ref().unwrap(), stdin).unwrap();

    let sandbox = SandboxImplementation::run(config.clone()).unwrap();
    let result = sandbox.wait().unwrap();

    let execution_result = ExecutionResult {
        result,
        stdout: fs::read_to_string(&config.stdout.unwrap()).unwrap(),
        stderr: fs::read_to_string(&config.stderr.unwrap()).unwrap(),
    };
    eprintln!("Result = {:?}", execution_result);
    execution_result
}
