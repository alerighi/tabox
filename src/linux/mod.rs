// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! This module contains the sandbox for Linux

mod filesystem;
mod seccomp_filter;

use crate::configuration::SandboxConfiguration;
use crate::result::{ExitStatus, ResourceUsage, SandboxExecutionResult};
use crate::util::set_resource_limit;
use crate::{Result, Sandbox};

use nix::sys::signal::{kill, Signal};
use nix::unistd::{self, Pid};
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr::null;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct LinuxSandbox {
    child_thread: JoinHandle<SandboxExecutionResult>,
}

impl Sandbox for LinuxSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        trace!("Run LinuxSandbox with config {:?}", config);

        // Start a child process to setup the sandboxhttps://www.reddit.com/r/AskReddit/
        let handle = thread::Builder::new()
            .name("Sandbox watcher".into())
            .spawn(move || watcher(config))?;

        Ok(LinuxSandbox {
            child_thread: handle,
        })
    }

    fn wait(self) -> Result<SandboxExecutionResult> {
        Ok(self.child_thread.join().unwrap())
    }

    fn is_secure() -> bool {
        true
    }
}

fn watcher(config: SandboxConfiguration) -> SandboxExecutionResult {
    let tempdir = tempdir::TempDir::new("tabox").expect("Cannot create temporary directory");
    let sandbox_path = tempdir.path();

    // uid/gid from outside the sandbox
    let uid = unistd::getuid();
    let gid = unistd::getgid();

    trace!(
        "Watcher process started, PID = {}, uid = {}, gid = {}",
        unistd::getpid(),
        uid,
        gid
    );

    // Start child in an unshared environment
    let child_pid = check_syscall!(libc::syscall(
        libc::SYS_clone,
        libc::CLONE_NEWIPC
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWUSER
            | libc::CLONE_NEWUTS
            | libc::SIGCHLD,
        null::<libc::c_void>(),
    )) as libc::pid_t;

    if child_pid == 0 {
        // Map current uid/gid to root/root inside the sandbox
        std::fs::write("/proc/self/setgroups", "deny").unwrap();
        std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid.as_raw())).unwrap();
        std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid.as_raw())).unwrap();

        // When parent dies, I want to die too
        check_syscall!(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL));

        // Start child process
        child(&config, sandbox_path);
    }

    let start_time = Instant::now();

    let killed = Arc::new(AtomicBool::new(false));

    // Start a thread that kills the process when the wall limit expires
    if let Some(limit) = config.wall_time_limit {
        let killed = killed.clone();
        thread::Builder::new()
            .name("Wall time watcher".into())
            .spawn(move || {
                thread::sleep(Duration::new(limit, 0));

                // Kill process if it didn't terminate in wall limit
                kill(Pid::from_raw(child_pid), Signal::SIGKILL)
                    .expect("Error killing child due to wall limit exceeded");

                killed.store(true, Ordering::SeqCst);
            })
            .expect("Error spawning wall time watcher thread");
    }

    // Wait process to terminate and get its resource consumption
    let mut status = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

    check_syscall!(libc::wait4(child_pid, &mut status, 0, &mut rusage));

    let result = SandboxExecutionResult {
        status: unsafe {
            if killed.load(Ordering::SeqCst) {
                ExitStatus::Killed
            } else if libc::WIFEXITED(status) {
                ExitStatus::ExitCode(libc::WEXITSTATUS(status))
            } else {
                ExitStatus::Signal(libc::WTERMSIG(status))
            }
        },
        resource_usage: ResourceUsage {
            memory_usage: rusage.ru_maxrss as usize * 1024,
            user_cpu_time: rusage.ru_utime.tv_usec as f64 / 1_000_000.0
                + rusage.ru_utime.tv_sec as f64,
            system_cpu_time: rusage.ru_stime.tv_usec as f64 / 1_000_000.0
                + rusage.ru_stime.tv_sec as f64,
            wall_time_usage: (Instant::now() - start_time).as_secs_f64(),
        },
    };

    trace!("Child terminated, result = {:?}", result);

    result
}

/// Child process
fn child(config: &SandboxConfiguration, sandbox_path: &Path) -> ! {
    assert_eq!(unistd::getpid().as_raw(), 1);
    assert_eq!(unistd::getuid().as_raw(), 0);
    assert_eq!(unistd::getgid().as_raw(), 0);

    let mut command = Command::new(&config.executable);

    command
        .env_clear()
        .envs(config.env.clone())
        .args(&config.args);

    if let Some(stdin) = &config.stdin {
        command.stdin(Stdio::from(
            File::open(stdin).expect("Cannot open stdin file"),
        ));
    }

    if let Some(stdout) = &config.stdout {
        command.stdout(Stdio::from(
            File::create(stdout).expect("Cannot open stdout file"),
        ));
    }

    if let Some(stderr) = &config.stderr {
        command.stderr(Stdio::from(
            File::create(stderr).expect("Cannot open stderr file"),
        ));
    }

    let config = config.clone();
    let sandbox_path = sandbox_path.to_owned();

    unsafe {
        // Execute right before exec()
        command.pre_exec(move || {
            filesystem::create(&config, &sandbox_path).expect("Error creating filesystem");
            setup_thread_affinity(&config).expect("Error setting thread affinity");
            enter_chroot(&config, &sandbox_path).expect("Error entering in chroot");
            setup_resource_limits(&config);
            setup_syscall_filter(&config);
            Ok(())
        });
    }

    command.exec();
    unreachable!();
}

/// Set cpu affinity
fn setup_thread_affinity(config: &SandboxConfiguration) -> nix::Result<()> {
    if let Some(core) = config.cpu_core {
        let mut cpu_set = nix::sched::CpuSet::new();
        cpu_set.set(core)?;
        nix::sched::sched_setaffinity(Pid::from_raw(0), &cpu_set)?
    }
    Ok(())
}

/// Enter the sandbox chroot and change directory
fn enter_chroot(config: &SandboxConfiguration, sandbox_path: &Path) -> nix::Result<()> {
    // Chroot into the sandbox
    unistd::chroot(sandbox_path)?;

    // Check that things exits inside
    assert!(config.executable.exists(), "Executable doesn't exist inside the sandbox chroot. Perhaps you need to mount some directories?");
    assert!(
        config.working_directory.exists(),
        "Working directory doesn't exists inside chroot. Maybe you need to mount it?"
    );

    // Change to  working directory
    unistd::chdir(&config.working_directory)?;
    Ok(())
}

/// Setup the Syscall filter
fn setup_syscall_filter(config: &SandboxConfiguration) {
    if let Some(syscall_filter) = &config.syscall_filter {
        let mut filter = seccomp_filter::SeccompFilter::new(syscall_filter.default_action);
        for (syscall, action) in &syscall_filter.rules {
            filter.filter(syscall, *action);
        }
        filter.load();
    }
}

/// Setup the resource limits
fn setup_resource_limits(config: &SandboxConfiguration) {
    if let Some(memory_limit) = config.memory_limit {
        set_resource_limit(libc::RLIMIT_AS, memory_limit);
    }

    if let Some(time_limit) = config.time_limit {
        set_resource_limit(libc::RLIMIT_CPU, time_limit);
    }

    // No core dumps
    set_resource_limit(libc::RLIMIT_CORE, 0);
}
