// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use crate::result::{ExitStatus, ResourceUsage};
use crate::util::{set_resource_limit, time};
use crate::{Result, Sandbox, SandboxConfiguration, SandboxExecutionResult};
use std::fs::File;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct MacOSSandbox {
    child: Child,
    start_time: f64,
    killed: Arc<AtomicBool>,
}

impl Sandbox for MacOSSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        let mut command = Command::new(&config.executable);

        unsafe {
            let config = config.clone();

            // This code get executed after the fork() and before the exec()
            command.pre_exec(move || {
                set_resource_limit(libc::RLIMIT_CORE, 0);

                if let Some(memory_limit) = config.memory_limit {
                    set_resource_limit(libc::RLIMIT_RSS, memory_limit); // this doesn't really work
                }

                if let Some(time_limit) = config.time_limit {
                    set_resource_limit(libc::RLIMIT_CPU, time_limit);
                }
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
                            check_syscall!(libc::kill(child_pid, libc::SIGSEGV));
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
                    check_syscall!(libc::kill(child_pid, libc::SIGKILL));

                    killed.store(true, Ordering::SeqCst);
                })?;
        }

        Ok(MacOSSandbox {
            child,
            start_time: time(),
            killed,
        })
    }

    fn wait(mut self) -> Result<SandboxExecutionResult> {
        let status = self.child.wait()?;

        let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

        // This doesn't really work in tests. Since when running `cargo test` all
        // tests are run in the same process, here you will get the resource usage
        // of all child created, including the rust compiler itself if a build was involved!
        // The solution is run the test that require checking CPU time and memory usage separated.
        // In production is shouldn't be a problem, since there is one and only one child,
        // that is the process we intend to measure its resource usage.
        // Unfortunately it doesn't seem that there is a wait4 function in the libc crate,
        // and this is strange since it's mentioned in the MacOS manpage WAIT(2)...
        // Whatever, it's good enough
        check_syscall!(libc::getrusage(libc::RUSAGE_CHILDREN, &mut rusage));

        Ok(SandboxExecutionResult {
            status: if self.killed.load(Ordering::SeqCst) {
                ExitStatus::Killed
            } else if let Some(exit_code) = status.code() {
                ExitStatus::ExitCode(exit_code)
            } else if let Some(signal) = status.signal() {
                ExitStatus::Signal(signal)
            } else {
                unreachable!()
            },
            resource_usage: ResourceUsage {
                memory_usage: rusage.ru_maxrss as usize,
                user_cpu_time: rusage.ru_utime.tv_usec as f64 / 1_000_000.0
                    + rusage.ru_utime.tv_sec as f64,
                system_cpu_time: rusage.ru_stime.tv_usec as f64 / 1_000_000.0
                    + rusage.ru_stime.tv_sec as f64,
                wall_time_usage: time() - self.start_time,
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
