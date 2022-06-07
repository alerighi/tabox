// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! This module contains types for the result of an execution

use serde::{Deserialize, Serialize};

use crate::util::strsignal;

/// Struct that contains the information about resource usage of the process
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Memory usage in bytes
    pub memory_usage: u64,

    /// User cpu time usage in seconds
    pub user_cpu_time: f64,

    /// System cpu time usage in seconds
    pub system_cpu_time: f64,

    /// Wall time usage
    pub wall_time_usage: f64,
}

/// Exit status of a sandbox process
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Process terminated with an exit code
    ExitCode(i32),

    /// Process was killed with a signal
    Signal(i32),

    /// Process was killed by the sandbox (e.g for exceeding wall time limit)
    Killed,
}

impl ExitStatus {
    /// True if the process executed correctly (return with exit status 0)
    pub fn success(self) -> bool {
        self == ExitStatus::ExitCode(0)
    }
}

/// struct that represents the execution result of a sandbox
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxExecutionResult {
    /// Exit status of the process
    pub status: ExitStatus,

    /// Information about the resource usage of the process
    pub resource_usage: ResourceUsage,
}

impl ExitStatus {
    /// Return the name of the signal, if the status is `ExitStatus::Signal`, otherwise `None` is
    /// returned.
    /// If the signal name is not available, `None` is returned.
    pub fn signal_name(&self) -> Option<String> {
        match self {
            ExitStatus::Signal(signal) => strsignal(*signal),
            _ => None,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn test_signal_name() {
        assert_eq!(
            Some("Segmentation fault: 11".into()),
            ExitStatus::Signal(11).signal_name()
        );
        assert!(ExitStatus::Killed.signal_name().is_none());
        assert!(ExitStatus::ExitCode(0).signal_name().is_none());
    }
}
