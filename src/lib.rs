// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! # tmbox
//!
//! A sandbox for task-maker and TuringArena
//!
//! ### What does it do
//! tmbox allows you to do two things:
//! - launch a process in a secure environment, where it cannot damage the existing machine
//! - measure and limit the resource (cpu time, memory) usage of the process

#[macro_use]
extern crate log;
extern crate serde;
extern crate serde_json;
extern crate tempdir;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub type SandboxImplementation = linux::LinuxSandbox;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub type SandboxImplementation = macos::MacOSSandbox;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("Sandbox not supported on your operating system");

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Convenience result type
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A structure that describes how a bind mount into the Sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindMount {
    /// Where to mount the directory inside the sandbox.
    pub target: PathBuf,

    /// Path of the directory to mount inside the sandbox
    pub source: PathBuf,

    /// Should the directory be writable or not
    pub writable: bool,
}

/// Describes a mountpoint inside the sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirectoryMount {
    /// Bind a directory of the system inside the sandbox
    Bind(BindMount),

    /// Mount a tmpfs in the specified path
    Tmpfs(PathBuf),
}

/// System call filter action
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum SyscallFilterAction {
    /// Allow all system calls
    Allow,

    /// Kill the process
    Kill,

    /// Return this errno
    Errno(u32),
}

/// Syscall filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallFilter {
    /// Default action to execute
    pub default_action: SyscallFilterAction,

    /// Sandbox filter rules in the form of (syscall_name, action)
    pub rules: Vec<(String, SyscallFilterAction)>,
}

/// struct that represents the configuration parameters
/// of a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfiguration {
    /// Time limit for the execution in seconds
    pub time_limit: Option<u64>,

    /// Memory limit fot the execution in bytes
    pub memory_limit: Option<u64>,

    /// Absolute path of the executable
    pub executable: PathBuf,

    /// Arguments to pass to the executable
    pub args: Vec<String>,

    /// Environment to pass to the sandbox
    pub env: Vec<(String, String)>,

    /// Allowed paths inside the sandbox
    pub mount_paths: Vec<DirectoryMount>,

    /// Working directory
    pub working_directory: PathBuf,

    /// Redirect stdin from this file
    pub stdin: Option<PathBuf>,

    /// Redirect stdout from this file
    pub stdout: Option<PathBuf>,

    /// Redirect stderr from this file
    pub stderr: Option<PathBuf>,

    /// Allow only these system calls in the sandbox
    pub syscall_filter: Option<SyscallFilter>,
}

/// Builder for the SandboxConfiguration
#[derive(Debug, Clone)]
pub struct SandboxConfigurationBuilder {
    time_limit: Option<u64>,
    memory_limit: Option<u64>,
    executable: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
    mount_paths: Vec<DirectoryMount>,
    working_directory: PathBuf,
    stdin: Option<PathBuf>,
    stdout: Option<PathBuf>,
    stderr: Option<PathBuf>,
    syscall_filter: Option<SyscallFilter>,
}

impl Default for SandboxConfigurationBuilder {
    fn default() -> Self {
        SandboxConfigurationBuilder {
            time_limit: None,
            memory_limit: None,
            executable: PathBuf::from("/bin/sh"),
            args: vec![],
            env: vec![],
            mount_paths: vec![],
            working_directory: PathBuf::from("/"),
            stdin: None,
            stdout: None,
            stderr: None,
            syscall_filter: None,
        }
    }
}

impl SandboxConfigurationBuilder {
    /// Build the sandbox configuration
    pub fn build(self) -> SandboxConfiguration {
        SandboxConfiguration {
            time_limit: self.time_limit,
            memory_limit: self.memory_limit,
            executable: self.executable,
            args: self.args,
            env: self.env,
            mount_paths: self.mount_paths,
            working_directory: self.working_directory,
            stdin: self.stdin,
            stdout: self.stdout,
            stderr: self.stderr,
            syscall_filter: self.syscall_filter,
        }
    }

    /// Set the time limit
    pub fn time_limit(&mut self, time_limit: u64) -> &Self {
        self.time_limit = Some(time_limit);
        self
    }

    /// Set the memory limit
    pub fn memory_limit(&mut self, memory_limit: u64) -> &Self {
        self.memory_limit = Some(memory_limit);
        self
    }

    /// Set the standard input file path
    pub fn stdin(&mut self, stdin: PathBuf) -> &Self {
        self.stdin = Some(stdin);
        self
    }

    /// Set the standard output file path
    pub fn stdout(&mut self, stdout: PathBuf) -> &Self {
        self.stdout = Some(stdout);
        self
    }

    /// Set the standard error file path
    pub fn stderr(&mut self, stderr: PathBuf) -> &Self {
        self.stderr = Some(stderr);
        self
    }

    /// Set the executable file path
    pub fn executable<P: Into<PathBuf>>(&mut self, executable: P) -> &Self {
        self.executable = executable.into();
        self
    }

    /// Set the working directory
    pub fn working_directory<P: Into<PathBuf>>(&mut self, working_directory: P) -> &Self {
        self.working_directory = working_directory.into();
        self
    }

    /// Add an argument to the program
    pub fn arg<S: Into<String>>(&mut self, arg: S) -> &Self {
        self.args.push(arg.into());
        self
    }

    /// Add an argument to the environment
    pub fn env<S: Into<String>, T: Into<String>>(&mut self, variable: S, value: T) -> &Self {
        self.env.push((variable.into(), value.into()));
        self
    }

    /// Add a mount point into the sandbox
    pub fn mount(&mut self, mount: DirectoryMount) -> &Self {
        self.mount_paths.push(mount);
        self
    }

    /// Install the syscall filter
    pub fn syscall_filter(&mut self, filter: SyscallFilter) -> &Self {
        self.syscall_filter = Some(filter);
        self
    }
}

/// Struct that contains the information about resource usage of the process
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Memory usage in bytes
    pub memory_usage: usize,

    /// User cpu time usage in seconds
    pub user_cpu_time: f64,

    /// System cpu time usage in seconds
    pub system_cpu_time: f64,
}

/// Exit status of a sandbox process
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Process terminated with an exit code
    ExitCode(i32),

    /// Process was killed with a signal
    Signal(i32),
}

impl ExitStatus {
    /// True if the process executed correctly (return with exit status 0)
    pub fn is_success(self) -> bool {
        self == ExitStatus::ExitCode(0)
    }
}

/// struct that rappresents the execution result of a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecutionResult {
    /// Exit status of the process
    pub status: ExitStatus,

    /// Information about the resource usage of the process
    pub resource_usage: ResourceUsage,
}

pub trait Sandbox {
    /// Execute the sandbox
    fn run(config: SandboxConfiguration) -> Result<Self>
    where
        Self: Sized;

    /// Wait the process to terminate, giving back the execution result
    fn wait(self) -> Result<SandboxExecutionResult>;

    /// Return true if the sandbox implementation is secure
    fn is_secure() -> bool;
}
