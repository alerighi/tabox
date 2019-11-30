// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};

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
