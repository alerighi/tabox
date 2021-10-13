// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! This module contains the sandbox for Linux

use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr::null;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{self, Pid};

use crate::{Result, Sandbox};
use crate::configuration::SandboxConfiguration;
use crate::result::{ExitStatus, ResourceUsage, SandboxExecutionResult};
use crate::util::{setup_resource_limits, wait};

mod filesystem;
mod seccomp_filter;

lazy_static! {
    /// PID of the child process, will be used to kill the child when SIGTERM or SIGINT is received.
    static ref CHILD_PID: Arc<AtomicI32> = Arc::new(AtomicI32::new(-1));
}

/// Handler of the SIGINT and SIGTERM signals. If the child PID is available a SIGKILL will be sent
/// to that process.
fn sigterm_handler() {
    let child_pid = CHILD_PID.load(Ordering::SeqCst);
    if child_pid > 0 {
        match kill(Pid::from_raw(child_pid), Signal::SIGKILL) {
            Ok(()) => info!("Killed child process {}", child_pid),
            Err(e) => error!("Cannot kill {}: {:?}", child_pid, e),
        }
    } else {
        warn!("Cannot stop the child since the pid is unknown");
    }
}

pub struct LinuxSandbox {
    child_thread: JoinHandle<SandboxExecutionResult>,
}

impl Sandbox for LinuxSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        trace!("Run LinuxSandbox with config {:?}", config);

        // Register a signal handler that kills the child
        unsafe { signal_hook::register(signal_hook::SIGTERM, sigterm_handler) }?;
        unsafe { signal_hook::register(signal_hook::SIGINT, sigterm_handler) }?;

        // Start a child process to setup the sandbox
        let handle = thread::Builder::new()
            .name("Sandbox watcher".into())
            .spawn(move || watcher(config).expect("Error starting sandbox watcher"))?;

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

fn watcher(config: SandboxConfiguration) -> Result<SandboxExecutionResult> {
    let tempdir = tempdir::TempDir::new("tabox")?;
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
    let child_pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_NEWIPC
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWUSER
                | libc::CLONE_NEWUTS
                | libc::SIGCHLD,
            null::<libc::c_void>(),
        )
    } as libc::pid_t;

    if child_pid < 0 {
        bail!("clone() error");
    }

    if child_pid == 0 {
        // Map current uid/gid to root/root inside the sandbox
        std::fs::write("/proc/self/setgroups", "deny")?;
        std::fs::write(
            "/proc/self/uid_map",
            format!("{} {} 1", config.uid, uid.as_raw()),
        )?;
        std::fs::write(
            "/proc/self/gid_map",
            format!("{} {} 1", config.gid, gid.as_raw()),
        )?;

        // When parent dies, I want to die too
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 } {
            bail!("Error calling prctl()");
        };

        // Start child process
        child(&config, sandbox_path)?;
    }

    // Store the PID of the child process for letting the signal handler kill the child
    CHILD_PID.store(child_pid, Ordering::SeqCst);

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
            })?;
    }

    // Wait child for completion
    let (status, resource_usage) = wait(child_pid)?;

    Ok(SandboxExecutionResult {
        status: if killed.load(Ordering::SeqCst) {
            ExitStatus::Killed
        } else {
            status
        },
        resource_usage: ResourceUsage {
            wall_time_usage: (Instant::now() - start_time).as_secs_f64(),
            ..resource_usage
        },
    })
}

/// Child process
fn child(config: &SandboxConfiguration, sandbox_path: &Path) -> Result<()> {
    assert_eq!(unistd::getpid().as_raw(), 1);

    let mut command = Command::new(&config.executable);

    command
        .env_clear()
        .envs(config.env.clone())
        .args(&config.args);

    if let Some(stdin) = &config.stdin {
        command.stdin(Stdio::from(File::open(stdin)?));
    }

    if let Some(stdout) = &config.stdout {
        command.stdout(Stdio::from(File::create(stdout)?));
    }

    if let Some(stderr) = &config.stderr {
        command.stderr(Stdio::from(File::create(stderr)?));
    }

    filesystem::create(&config, &sandbox_path)?;
    setup_thread_affinity(&config)?;
    enter_chroot(&config, &sandbox_path)?;
    setup_resource_limits(&config)?;
    setup_syscall_filter(&config)?;

    // This can only return Err... nice!
    Err(command.exec()).context("Failed to exec")
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
fn setup_syscall_filter(config: &SandboxConfiguration) -> Result<()> {
    if let Some(syscall_filter) = &config.syscall_filter {
        let mut filter = seccomp_filter::SeccompFilter::new(syscall_filter.default_action)?;
        for (syscall, action) in &syscall_filter.rules {
            filter.filter(syscall, *action)?;
        }
        filter.load()?;
    }
    Ok(())
}
