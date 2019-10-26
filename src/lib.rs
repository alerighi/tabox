use std::path::PathBuf;

#[derive(Debug)]
pub enum TimeLimit {
    Unlimited,
    MilliSeconds(usize),
}

#[derive(Debug)]
pub enum MemoryLimit {
    Unlimited, 
    Bytes(usize),
}

/// struct that rappresents the configuration parameters
/// of a sandbox
#[derive(Debug)]
pub struct SandboxConfiguration {
    /// time limit for the execution
    time_limit: TimeLimit,

    /// memory limit fot the execution
    memory_limit: MemoryLimit,

    /// absolute path of the executable
    executable: PathBuf,

    /// arguments to pass to the executable
    args: Vec<String>,

    /// allowed paths inside the sandbox
    allowed_paths: Vec<PathBuf>,

    /// redirect stdin from this file
    stdin: Option<PathBuf>,

    /// redirect stdout from this file
    stdout: Option<PathBuf>,

    /// redirect stderr from this file
    stderr: Option<PathBuf>,
}

/// struct that rappresents the execution result of a sandbox
#[derive(Debug)]
pub struct SandboxExecutionResult {
    /// return code of the process
    pub return_code: u8,

    /// signal of exit of the process
    pub signal: u8,

    /// true if the process was killed 
    pub was_killed: bool,

    /// memory usage in bytes
    pub memory_usage_bytes: u64,

    /// time usage in milliseconds 
    pub time_usage_milliseconds: u64,
}

