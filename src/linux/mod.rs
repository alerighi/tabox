// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

extern crate core_affinity;
extern crate errno;
extern crate libc;
extern crate seccomp_sys;
extern crate tempdir;

mod filesystem;
mod seccomp_filter;

use crate::configuration::SandboxConfiguration;
use crate::result::{ExitStatus, ResourceUsage, SandboxExecutionResult};
use crate::util::{set_resource_limit, time};
use crate::{Result, Sandbox};

use libc::*;
use seccomp_filter::*;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::IntoRawFd;
use std::path::Path;
use std::ptr::null;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use tempdir::TempDir;

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
    let tempdir = TempDir::new("tabox").expect("Cannot create temporary directory");
    let sandbox_path = tempdir.path();

    // uid/gid from outside the sandbox
    let uid = unsafe { getuid() };
    let gid = unsafe { getgid() };

    trace!(
        "Watcher process started, PID = {}, uid = {}, gid = {}",
        unsafe { getpid() },
        uid,
        gid
    );

    let start_time = time();

    // Start child in an unshared environment
    let child_pid = check_syscall!(syscall(
        SYS_clone,
        CLONE_NEWIPC
            | CLONE_NEWNET
            | CLONE_NEWNS
            | CLONE_NEWPID
            | CLONE_NEWUSER
            | CLONE_NEWUTS
            | SIGCHLD,
        null::<c_void>(),
    )) as pid_t;

    if child_pid == 0 {
        // Map current uid/gid to root/root inside the sandbox
        std::fs::write("/proc/self/setgroups", "deny").unwrap();
        std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid)).unwrap();
        std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid)).unwrap();

        // When parent dies, I want to die too
        check_syscall!(prctl(PR_SET_PDEATHSIG, SIGKILL));

        // Start child process
        child(&config, sandbox_path);
    }

    let killed = Arc::new(AtomicBool::new(false));

    // Start a thread that kills the process when the wall limit expires
    if let Some(limit) = config.wall_time_limit {
        let killed = killed.clone();
        thread::Builder::new()
            .name("Wall time watcher".into())
            .spawn(move || {
                thread::sleep(Duration::new(limit, 0));

                // Kill process if it didn't terminate in wall limit
                check_syscall!(kill(child_pid, SIGKILL));

                killed.store(true, Ordering::SeqCst);
            })
            .expect("Error spawning wall time watcher thread");
    }

    // Wait process to terminate and get its resource consumption
    let mut status = 0;
    let mut rusage: rusage = unsafe { std::mem::zeroed() };

    check_syscall!(wait4(child_pid, &mut status, 0, &mut rusage));

    let end_time = time();

    let result = SandboxExecutionResult {
        status: unsafe {
            if killed.load(Ordering::SeqCst) {
                ExitStatus::Killed
            } else if WIFEXITED(status) {
                ExitStatus::ExitCode(WEXITSTATUS(status))
            } else {
                ExitStatus::Signal(WTERMSIG(status))
            }
        },
        resource_usage: ResourceUsage {
            memory_usage: rusage.ru_maxrss as usize * 1024,
            user_cpu_time: rusage.ru_utime.tv_usec as f64 / 1_000_000.0
                + rusage.ru_utime.tv_sec as f64,
            system_cpu_time: rusage.ru_stime.tv_usec as f64 / 1_000_000.0
                + rusage.ru_stime.tv_sec as f64,
            wall_time_usage: end_time - start_time,
        },
    };

    trace!("Child terminated, result = {:?}", result);

    result
}

/// Child process
fn child(config: &SandboxConfiguration, sandbox_path: &Path) -> ! {
    assert_eq!(unsafe { getpid() }, 1);
    assert_eq!(unsafe { getuid() }, 0);
    assert_eq!(unsafe { getgid() }, 0);

    filesystem::create(config, sandbox_path);
    setup_resource_limits(config);
    setup_syscall_filter(config);
    setup_io_redirection(config);
    setup_thread_affinity(config);
    enter_chroot(config, sandbox_path);
    exec_child(config);
}

/// Set cpu affinity
fn setup_thread_affinity(config: &SandboxConfiguration) {
    if let Some(core) = config.cpu_core {
        unsafe {
            let mut cpu: cpu_set_t = std::mem::zeroed();
            CPU_ZERO(&mut cpu);
            CPU_SET(core as usize, &mut cpu);
            check_syscall!(sched_setaffinity(1, 1, &cpu));
        }
    }
}

/// Enter the sandbox chroot and change directory
fn enter_chroot(config: &SandboxConfiguration, sandbox_path: &Path) {
    // Chroot into the sandbox
    let root = CString::new(sandbox_path.to_str().unwrap()).unwrap();
    check_syscall!(chroot(root.as_ptr()));

    // Change to  working directory
    let cwd = CString::new(config.working_directory.to_str().unwrap()).unwrap();
    check_syscall!(chdir(cwd.as_ptr()));
}

fn exec_child(config: &SandboxConfiguration) -> ! {
    assert!(config.executable.exists(), "Executable doesn't exist inside the sandbox chroot. Perhaps you need to mount some directories?");

    // Build args array
    let mut args: Vec<CString> = Vec::new();
    args.push(CString::new(config.executable.to_str().unwrap()).unwrap());
    for arg in &config.args {
        args.push(CString::new(arg.clone()).unwrap());
    }

    // Build environment array
    let mut env: Vec<CString> = Vec::new();
    for (variable, value) in &config.env {
        env.push(CString::new(format!("{}={}", variable, value)).unwrap());
    }

    check_syscall!(execve(
        args[0].as_ptr(),
        to_c_array(&args).as_ptr(),
        to_c_array(&env).as_ptr()
    ));
    unreachable!();
}

/// Convert CString array to null-terminated C array
fn to_c_array(a: &[CString]) -> Vec<*const c_char> {
    let mut result: Vec<*const c_char> = Vec::new();
    for s in a {
        result.push(s.as_ptr());
    }
    result.push(null());
    result
}

/// Setup the Syscall filter
fn setup_syscall_filter(config: &SandboxConfiguration) {
    if let Some(syscall_filter) = &config.syscall_filter {
        let mut filter = SeccompFilter::new(syscall_filter.default_action);
        for (syscall, action) in &syscall_filter.rules {
            filter.filter(syscall, *action);
        }
        filter.load();
    }
}

/// Setup stdio file redirection
fn setup_io_redirection(config: &SandboxConfiguration) {
    // Setup io redirection
    if let Some(stdin) = &config.stdin {
        let file = File::open(&stdin)
            .unwrap_or_else(|_| panic!("Cannot open stdin file {:?} for reading", stdin));
        check_syscall!(dup2(file.into_raw_fd(), 0));
    }

    if let Some(stdout) = &config.stdout {
        let file = File::create(stdout)
            .unwrap_or_else(|_| panic!("Cannot open stdout file {:?} for writing", stdout));
        check_syscall!(dup2(file.into_raw_fd(), 1));
    }

    if let Some(stderr) = &config.stderr {
        let file = File::create(stderr)
            .unwrap_or_else(|_| panic!("Cannot open stderr file {:?} for writing", stderr));
        check_syscall!(dup2(file.into_raw_fd(), 2));
    }
}

/// Setup the resource limits
fn setup_resource_limits(config: &SandboxConfiguration) {
    if let Some(memory_limit) = config.memory_limit {
        set_resource_limit(RLIMIT_AS, memory_limit);
    }

    if let Some(time_limit) = config.time_limit {
        set_resource_limit(RLIMIT_CPU, time_limit);
    }

    // No core dumps
    set_resource_limit(RLIMIT_CORE, 0);
}
