// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0
//! This module contains the sandbox for MacOS

use crate::configuration::SandboxConfiguration;
use crate::result::{ExitStatus, ResourceUsage, SandboxExecutionResult};
use crate::util::{setup_resource_limits, wait};
use crate::{Result, Sandbox};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub struct MacOSSandbox {
    child: Child,
    start_time: Instant,
    killed: Arc<AtomicBool>,
}

impl Sandbox for MacOSSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        let mut command = Command::new(&config.executable);

        unsafe {
            let config = config.clone();

            // This code get executed after the fork() and before the exec()
            command.pre_exec(move || {
                setup_resource_limits(&config).expect("Error setting resource limits");
                Ok(())
            });
        }

        command
            .args(config.args)
            .env_clear()
            .envs(config.env)
            .current_dir(config.working_directory);

        if let Some(stdin) = config.stdin {
            command.stdin(Stdio::from(File::open(stdin)?));
        }

        if let Some(stdout) = config.stdout {
            command.stdout(Stdio::from(File::create(stdout)?));
        }

        if let Some(stderr) = config.stderr {
            command.stderr(Stdio::from(File::create(stderr)?));
        }

        // Spawn child
        let child = command.spawn()?;

        let killed = Arc::new(AtomicBool::new(false));
        let child_pid = child.id() as i32;

        if let Some(memory_limit) = config.memory_limit {
            // This thread monitors the memory used by the process and kills it when the limit is exceeded
            thread::Builder::new()
                .name("TABox memory watcher".into())
                .spawn(move || {
                    loop {
                        if get_macos_memory_usage(child_pid) > memory_limit {
                            // Kill process if memory limit exceeded.
                            // Send SIGSEGV since it's the same that sends Linux.
                            kill(Pid::from_raw(child_pid), Signal::SIGSEGV)
                                .expect("Error killing child due to memory limit exceeded");
                        }

                        thread::sleep(Duration::new(0, 1_000));
                    }
                })?;
        }

        if let Some(limit) = config.wall_time_limit {
            let killed = killed.clone();

            // This thread monitors the wall time of the process and kills it when the limit is exceeded
            thread::Builder::new()
                .name("TABox Wall time watcher".into())
                .spawn(move || {
                    thread::sleep(Duration::new(limit, 0));

                    // Kill process if it didn't terminate in wall limit
                    kill(Pid::from_raw(child_pid), Signal::SIGKILL)
                        .expect("Error killing child due to wall limit exceeded");

                    killed.store(true, Ordering::SeqCst);
                })?;
        }

        Ok(MacOSSandbox {
            child,
            start_time: Instant::now(),
            killed,
        })
    }

    fn wait(self) -> Result<SandboxExecutionResult> {
        // Wait child for completion
        let (status, resource_usage) = wait(self.child.id() as libc::pid_t)?;

        Ok(SandboxExecutionResult {
            status: if killed.load(Ordering::SeqCst) {
                ExitStatus::Killed
            } else {
                status
            },
            resource_usage: ResourceUsage {
                wall_time_usage: (Instant::now() - self.start_time).as_secs_f64(),
                ..resource_usage
            },
        })
    }

    fn is_secure() -> bool {
        false
    }
}

/// Get the process memory usage in bytes calling PS
fn get_macos_memory_usage(child_pid: i32) -> u64 {
    let result = Command::new("ps")
        .arg("-o")
        .arg("rss=")
        .arg(format!("{}", child_pid))
        .output()
        .unwrap();

    std::str::from_utf8(&result.stdout)
        .unwrap()
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
        * 1024
}
