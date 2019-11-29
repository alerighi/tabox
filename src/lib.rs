#[macro_use]
extern crate log;
extern crate derive_builder;
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

use derive_builder::Builder;
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
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(setter(into))]
pub struct SandboxConfiguration {
    /// time limit for the execution in seconds
    #[builder(default)]
    pub time_limit: Option<u64>,

    /// memory limit fot the execution in bytes
    #[builder(default)]
    pub memory_limit: Option<u64>,

    /// absolute path of the executable
    pub executable: PathBuf,

    /// arguments to pass to the executable
    #[builder(default)]
    pub args: Vec<String>,

    /// environment to pass to the sandbox
    #[builder(default)]
    pub env: Vec<(String, String)>,

    /// allowed paths inside the sandbox
    pub mount_paths: Vec<DirectoryMount>,

    /// working directory
    #[builder(default = "PathBuf::from(\"/\")")]
    pub working_directory: PathBuf,

    /// redirect stdin from this file
    #[builder(default)]
    pub stdin: Option<PathBuf>,

    /// redirect stdout from this file
    #[builder(default)]
    pub stdout: Option<PathBuf>,

    /// redirect stderr from this file
    #[builder(default)]
    pub stderr: Option<PathBuf>,

    /// Allow only these system calls in the sandbox
    #[builder(default)]
    pub syscall_filter: Option<SyscallFilter>,
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
