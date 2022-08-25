// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Module that contains the configuration of the sandbox

use std::ffi::OsString;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::syscall_filter::SyscallFilter;

/// Describes a mountpoint inside the sandbox
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectoryMount {
    /// Where to mount the directory inside the sandbox.
    pub target: PathBuf,

    /// Path of the directory to mount inside the sandbox
    pub source: PathBuf,

    /// Should the directory be writable or not
    pub writable: bool,
}

/// struct that represents the configuration parameters
/// of a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfiguration {
    /// Time limit for the execution in seconds
    pub time_limit: Option<u64>,

    /// Memory limit for the execution in bytes
    pub memory_limit: Option<u64>,

    /// Stack limit for the execution in bytes
    pub stack_limit: Option<u64>,

    /// Absolute path of the executable
    pub executable: PathBuf,

    /// Arguments to pass to the executable
    pub args: Vec<OsString>,

    /// Environment to pass to the sandbox
    pub env: Vec<(OsString, OsString)>,

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

    /// Mount a r/w tmpfs in /tmp and /dev/shm
    pub mount_tmpfs: bool,

    /// Wall time limit
    pub wall_time_limit: Option<u64>,

    /// Set on which CPU core to run the sandbox
    pub cpu_core: Option<usize>,

    /// UID of the user inside the sandbox
    pub uid: usize,

    /// GID of the user inside the sandbox
    pub gid: usize,

    /// Mount /proc
    pub mount_proc: bool,
}

impl Default for SandboxConfiguration {
    fn default() -> Self {
        SandboxConfiguration {
            time_limit: None,
            memory_limit: None,
            stack_limit: None,
            executable: PathBuf::from("/bin/sh"),
            args: vec![],
            env: vec![],
            mount_paths: vec![],
            working_directory: PathBuf::from("/"),
            stdin: None,
            stdout: None,
            stderr: None,
            syscall_filter: None,
            mount_tmpfs: false,
            wall_time_limit: None,
            cpu_core: None,
            uid: 0,
            gid: 0,
            mount_proc: false,
        }
    }
}

impl SandboxConfiguration {
    /// Build the sandbox configuration
    pub fn build(&self) -> SandboxConfiguration {
        self.clone()
    }

    /// Set the time limit in seconds
    pub fn time_limit(&mut self, time_limit: u64) -> &mut Self {
        self.time_limit = Some(time_limit);
        self
    }

    /// Set the memory limit, in **bytes**
    pub fn memory_limit(&mut self, memory_limit: u64) -> &mut Self {
        self.memory_limit = Some(memory_limit);
        self
    }

    /// Set the stack limit, in **bytes**
    pub fn stack_limit(&mut self, stack_limit: u64) -> &mut Self {
        self.stack_limit = Some(stack_limit);
        self
    }

    /// Set the standard input file path
    pub fn stdin<P: Into<PathBuf>>(&mut self, stdin: P) -> &mut Self {
        self.stdin = Some(stdin.into());
        self
    }

    /// Set the standard output file path
    pub fn stdout<P: Into<PathBuf>>(&mut self, stdout: P) -> &mut Self {
        self.stdout = Some(stdout.into());
        self
    }

    /// Set the standard error file path
    pub fn stderr<P: Into<PathBuf>>(&mut self, stderr: P) -> &mut Self {
        self.stderr = Some(stderr.into());
        self
    }

    /// Set the executable file path
    pub fn executable<P: Into<PathBuf>>(&mut self, executable: P) -> &mut Self {
        self.executable = executable.into();
        self
    }

    /// Set the working directory
    pub fn working_directory<P: Into<PathBuf>>(&mut self, working_directory: P) -> &mut Self {
        self.working_directory = working_directory.into();
        self
    }

    /// Add an argument to the program
    pub fn arg<S: Into<OsString>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    /// Add an argument to the environment
    pub fn env<S: Into<OsString>, T: Into<OsString>>(
        &mut self,
        variable: S,
        value: T,
    ) -> &mut Self {
        self.env.push((variable.into(), value.into()));
        self
    }

    /// Add a mount point into the sandbox
    pub fn mount<P, Q>(&mut self, source: P, target: Q, writable: bool) -> &mut Self
    where
        P: Into<PathBuf>,
        Q: Into<PathBuf>,
    {
        self.mount_paths.push(DirectoryMount {
            source: source.into(),
            target: target.into(),
            writable,
        });
        self
    }

    /// Install the syscall filter
    pub fn syscall_filter(&mut self, filter: SyscallFilter) -> &mut Self {
        self.syscall_filter = Some(filter);
        self
    }

    /// Mount a r/w tmpfs in /tmp and /dev/shm
    pub fn mount_tmpfs(&mut self, value: bool) -> &mut Self {
        self.mount_tmpfs = value;
        self
    }

    /// Set wall time limit
    pub fn wall_time_limit(&mut self, value: u64) -> &mut Self {
        self.wall_time_limit = Some(value);
        self
    }

    /// Run the sandbox on the specified cpu core
    pub fn run_on_core(&mut self, value: usize) -> &mut Self {
        self.cpu_core = Some(value);
        self
    }

    /// Set the UID of the user inside the sandbox
    pub fn uid(&mut self, uid: usize) -> &mut Self {
        self.uid = uid;
        self
    }

    /// Set the GID of the user inside the sandbox
    pub fn gid(&mut self, gid: usize) -> &mut Self {
        self.gid = gid;
        self
    }

    /// Set mount /proc
    pub fn mount_proc(&mut self, mount_proc: bool) -> &mut Self {
        self.mount_proc = mount_proc;
        self
    }
}
