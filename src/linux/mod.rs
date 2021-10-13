// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! This module contains the sandbox for Linux

use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::ptr::null;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use anyhow::{anyhow, bail, Context};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{self, Gid, Pid, Uid};

use crate::configuration::SandboxConfiguration;
use crate::result::{ExitStatus, ResourceUsage, SandboxExecutionResult};
use crate::util::{setup_resource_limits, start_wall_time_watcher, strerror, wait};
use crate::{Result, Sandbox};

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
    child_thread: JoinHandle<Result<SandboxExecutionResult>>,
}

impl Sandbox for LinuxSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        trace!("Run LinuxSandbox with config {:?}", config);

        // Register a signal handler that kills the child
        unsafe { signal_hook::register(signal_hook::SIGTERM, sigterm_handler) }
            .context("Failed to register SIGTERM handler")?;
        unsafe { signal_hook::register(signal_hook::SIGINT, sigterm_handler) }
            .context("Failed to register SIGINT handler")?;

        // Start a child process to setup the sandbox
        let handle = thread::Builder::new()
            .name("Sandbox watcher".into())
            .spawn(move || watcher(config))
            .context("Failed to spawn sandbox watcher thread")?;

        Ok(LinuxSandbox {
            child_thread: handle,
        })
    }

    fn wait(self) -> Result<SandboxExecutionResult> {
        let result = self
            .child_thread
            .join()
            .map_err(|e| anyhow!("Watcher thread panicked: {:?}", e))?
            .context("Watcher thread failed")?;
        Ok(result)
    }

    fn is_secure() -> bool {
        true
    }
}
fn watcher(config: SandboxConfiguration) -> Result<SandboxExecutionResult> {
    let tempdir = tempdir::TempDir::new("tabox").context("Failed to create sandbox tempdir")?;
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

    enum ErrorMessage {
        NoError,
        Error(usize, [char; 1024]),
    }

    // Allocate some memory that the forked process can use to write the error. This memory is
    // page-aligned, which is hopefully enough for ErrorMessage.
    let shared = unsafe {
        std::mem::transmute(libc::mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<ErrorMessage>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            0,
            0,
        ))
    };
    // Cleanup the shared memory: by default there is no error (we cannot set it after because the
    // child process execs and this memory will be unreachable).
    unsafe { std::ptr::write(shared, ErrorMessage::NoError) };

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
        bail!("clone() error: {}", strerror());
    }

    if child_pid == 0 {
        if let Err(err) = child(&config, sandbox_path, uid, gid) {
            error!("Child failed: {:?}", err);

            // prepare a buffer where to write the error message
            let message = format!("{:?}", err);
            let message = message.chars().take(1024).collect::<Vec<_>>();
            let mut buffer = ['\0'; 1024];
            buffer[..message.len()].copy_from_slice(&message);

            // Write the error message to the shared memory. This is safe since the parent will not
            // read from it until this process has completely exited.
            let error = ErrorMessage::Error(message.len(), buffer);
            unsafe { std::ptr::write(shared, error) };
        } else {
            unreachable!("The child process must exec");
        }
    }

    // Store the PID of the child process for letting the signal handler kill the child
    CHILD_PID.store(child_pid, Ordering::SeqCst);

    let start_time = Instant::now();

    let killed = Arc::new(AtomicBool::new(false));

    // Start a thread that kills the process when the wall limit expires
    if let Some(limit) = config.wall_time_limit {
        start_wall_time_watcher(limit, child_pid, killed.clone())?;
    }

    // Wait child for completion
    let (status, resource_usage) = wait(child_pid).context("Failed to wait for child process")?;

    // Read from shared memory if there was an error with the sandbox. At this point the child
    // process has for sure exited, so it's safe to read.
    if let ErrorMessage::Error(len, error) = unsafe { std::ptr::read(shared) } {
        let message = error.iter().take(len).collect::<String>();
        bail!("{}", message);
    }

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
fn child(config: &SandboxConfiguration, sandbox_path: &Path, uid: Uid, gid: Gid) -> Result<()> {
    // Map current uid/gid to root/root inside the sandbox
    std::fs::write("/proc/self/setgroups", "deny")
        .context("Failed to write /proc/self/setgroups")?;
    std::fs::write(
        "/proc/self/uid_map",
        format!("{} {} 1", config.uid, uid.as_raw()),
    )
    .context("Failed to write /proc/self/uid_map")?;
    std::fs::write(
        "/proc/self/gid_map",
        format!("{} {} 1", config.gid, gid.as_raw()),
    )
    .context("Failed to write /proc/self/gid_map")?;

    // When parent dies, I want to die too
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 } {
        bail!("Error calling prctl(): {}", strerror());
    };

    assert_eq!(unistd::getpid().as_raw(), 1);

    let mut command = Command::new(&config.executable);

    command
        .env_clear()
        .envs(config.env.clone())
        .args(&config.args);

    if let Some(stdin) = &config.stdin {
        let stdin = File::open(stdin)
            .with_context(|| format!("Failed to open stdin file at {}", stdin.display()))?;
        command.stdin(stdin);
    }

    if let Some(stdout) = &config.stdout {
        let stdout = File::create(stdout)
            .with_context(|| format!("Failed to open stdout file at {}", stdout.display()))?;
        command.stdout(stdout);
    }

    if let Some(stderr) = &config.stderr {
        let stderr = File::create(stderr)
            .with_context(|| format!("Failed to open stderr file at {}", stderr.display()))?;
        command.stderr(stderr);
    }

    filesystem::create(&config, &sandbox_path).context("Failed to create sandbox filesystem")?;
    setup_thread_affinity(&config).context("Failed to setup thread affinity")?;
    enter_chroot(&config, &sandbox_path).context("Failed to enter chroot")?;
    setup_resource_limits(&config).context("Failed to setup rlimits")?;
    setup_syscall_filter(&config).context("Failed to setup syscall filter")?;

    // This can only return Err... nice!
    Err(command.exec()).context("Failed to exec child process")
}

/// Set cpu affinity
fn setup_thread_affinity(config: &SandboxConfiguration) -> Result<()> {
    if let Some(core) = config.cpu_core {
        let mut cpu_set = nix::sched::CpuSet::new();
        cpu_set.set(core)?;
        nix::sched::sched_setaffinity(Pid::from_raw(0), &cpu_set)
            .with_context(|| format!("Failed to set sched_setaffinity(0, {:?})", cpu_set))?
    }
    Ok(())
}

/// Enter the sandbox chroot and change directory
fn enter_chroot(config: &SandboxConfiguration, sandbox_path: &Path) -> Result<()> {
    // Chroot into the sandbox
    unistd::chroot(sandbox_path).context("Failed to chroot")?;

    // Check that things exits inside
    if !config.executable.exists() {
        bail!("Executable doesn't exist inside the sandbox chroot. Perhaps you need to mount some directories?");
    }
    if !config.working_directory.exists() {
        bail!("Working directory doesn't exists inside chroot. Maybe you need to mount it?");
    }

    // Change to working directory
    unistd::chdir(&config.working_directory).context("Failed to chdir")?;
    Ok(())
}

/// Setup the Syscall filter
fn setup_syscall_filter(config: &SandboxConfiguration) -> Result<()> {
    if let Some(syscall_filter) = &config.syscall_filter {
        let mut filter = seccomp_filter::SeccompFilter::new(syscall_filter.default_action)
            .context("Failed to setup SeccompFilter")?;
        for (syscall, action) in &syscall_filter.rules {
            filter.filter(syscall, *action).with_context(|| {
                format!("Failed to add syscall filter: {} {:?}", syscall, action)
            })?;
        }
        filter.load().context("Failed to load syscall filter")?;
    }
    Ok(())
}
