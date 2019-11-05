#[macro_use]
extern crate log;
extern crate serde;
extern crate serde_json;
extern crate derive_builder;
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

use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use derive_builder::Builder;

/// Convenience result type
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// struct that rappresents the configuration parameters
/// of a sandbox
#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
#[builder(setter(into))]
pub struct SandboxConfiguration {
    /// time limit for the execution in seconds
    #[builder(default)]
    time_limit: Option<u64>,

    /// memory limit fot the execution in bytes
    #[builder(default)]
    memory_limit: Option<u64>,

    /// absolute path of the executable
    executable: PathBuf,

    /// arguments to pass to the executable
    #[builder(default)]
    args: Vec<String>,

    /// environment to pass to the sandbox
    #[builder(default)]
    env: Vec<String>,

    /// allowed paths inside the sandbox
    mount_paths: Vec<PathBuf>,

    /// working directory
    #[builder(default = "PathBuf::from(\"/\")")]
    working_directory: PathBuf,

    /// redirect stdin from this file
    #[builder(default)]
    stdin: Option<PathBuf>,

    /// redirect stdout from this file
    #[builder(default)]
    stdout: Option<PathBuf>,

    /// redirect stderr from this file
    #[builder(default)]
    stderr: Option<PathBuf>,

    /// deny the system calls in this vector
    #[builder(default)]
    syscall_filter: Option<Vec<String>>,
}

/// Struct that contains the information about resource usage of the process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Memory usage in bytes
    pub memory_usage: usize,

    /// User cpu time usage in seconds
    pub user_cpu_time: f64,

    /// System cpu time usage in seconds
    pub system_cpu_time: f64,
}

/// struct that rappresents the execution result of a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecutionResult {
    /// Return code of the process, if terminated correctly
    pub return_code: Option<i32>,

    /// Signal of exit of the process, if killed with a signal
    pub signal: Option<i32>,

    /// Information about the resource usage of the process
    pub resource_usage: ResourceUsage,
}

pub trait Sandbox {
    /// Execute the sandbox
    fn run(config: SandboxConfiguration) -> Result<Self> where Self: Sized;

    /// Wait the process to terminate, giving back the execution result
    fn wait(self) -> Result<SandboxExecutionResult>;

    /// Return true if the sandbox implementation is secure
    fn is_secure() -> bool;
}
