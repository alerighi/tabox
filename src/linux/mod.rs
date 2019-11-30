// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate errno;
extern crate libc;
extern crate seccomp_sys;
extern crate tempdir;

use crate::configuration::{DirectoryMount, SandboxConfiguration};
use crate::result::{ExitStatus, ResourceUsage, SandboxExecutionResult};
use crate::{Result, Sandbox};

use libc::*;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::IntoRawFd;
use std::ptr::null;
use tempdir::TempDir;

macro_rules! check_syscall {
    ($call:expr) => {{
        let result = $call;
        trace!("{} = {}", stringify!($call), result);
        if result < 0 {
            panic!(
                "{} failed with exit code {} ({})",
                stringify!($call),
                result,
                errno::errno()
            );
        }
        result
    }};
}

mod seccomp_filter;

use seccomp_filter::*;
use std::fs;
use std::path::{Path, PathBuf};

pub struct LinuxSandbox {
    tempdir: TempDir,
    child_pid: pid_t,
}

impl Sandbox for LinuxSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        trace!("Run LinuxSandbox with config {:?}", config);

        let tempdir = TempDir::new("tabox")?;

        // Start a child process to setup the sandbox
        match unsafe { fork() } {
            0 => unsafe { watcher(config, tempdir.path().into()) },
            child_pid if child_pid > 0 => Ok(LinuxSandbox { tempdir, child_pid }),
            _ => Err("Error forking process".into()),
        }
    }

    fn wait(self) -> Result<SandboxExecutionResult> {
        trace!(
            "Sandbox (dir = {:?}) waiting for child (PID = {}) completion",
            self.tempdir,
            self.child_pid
        );

        // Wait watcher to terminate
        let mut status = -1;

        if unsafe { waitpid(self.child_pid, &mut status, 0) } < 0 || status != 0 {
            return Err("Child process error".into());
        }

        let result = fs::read_to_string(self.tempdir.path().join("result.json"))?;
        let result = serde_json::from_str(&result)?;
        Ok(result)
    }

    fn is_secure() -> bool {
        true
    }
}

unsafe fn watcher(config: SandboxConfiguration, sandbox_path: PathBuf) -> ! {
    // uid/gid from outside the sandbox
    let uid = getuid();
    let gid = getgid();

    trace!(
        "Watcher process started, PID = {}, uid = {}, gid = {}",
        getpid(),
        uid,
        gid
    );

    // Enter unshared namespace
    check_syscall!(unshare(
        CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS
    ));

    // Fork to become pid 1
    let child_pid = check_syscall!(fork());

    if child_pid == 0 {
        // Map current uid/gid to root/root inside the sandbox
        std::fs::write("/proc/self/setgroups", "deny").unwrap();
        std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid)).unwrap();
        std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid)).unwrap();

        // Start child process
        child(&config, &sandbox_path.join("box"));
    }

    // Wait process to terminate and get its resource consumption
    let mut status = 0;
    let mut rusage: rusage = std::mem::zeroed();

    check_syscall!(wait4(child_pid, &mut status, 0, &mut rusage));

    let result = SandboxExecutionResult {
        status: if WIFEXITED(status) {
            ExitStatus::ExitCode(WEXITSTATUS(status))
        } else {
            ExitStatus::Signal(WTERMSIG(status))
        },
        resource_usage: ResourceUsage {
            memory_usage: rusage.ru_maxrss as usize * 1024,
            user_cpu_time: rusage.ru_utime.tv_usec as f64 / 1_000_000.0
                + rusage.ru_utime.tv_sec as f64,
            system_cpu_time: rusage.ru_stime.tv_usec as f64 / 1_000_000.0
                + rusage.ru_stime.tv_sec as f64,
        },
    };

    trace!("Child terminated, result = {:?}", result);

    // Write status to file
    let result_json = serde_json::to_string(&result).unwrap();
    fs::write(sandbox_path.join("result.json"), result_json).unwrap();

    // Exit correctly
    std::process::exit(0);
}

unsafe fn child(config: &SandboxConfiguration, sandbox_path: &Path) -> ! {
    assert_eq!(getpid(), 1);
    assert_eq!(getuid(), 0);
    assert_eq!(getgid(), 0);

    setup_filesystem(config, sandbox_path);
    setup_resource_limits(config);
    setup_syscall_filter(config);
    setup_io_redirection(config);
    enter_chroot(config, sandbox_path);
    exec_child(config);
}

/// Enter the sandbox chroot and change directory
unsafe fn enter_chroot(config: &SandboxConfiguration, sandbox_path: &Path) {
    // Chroot into the sandbox
    let root = CString::new(sandbox_path.to_str().unwrap()).unwrap();
    check_syscall!(chroot(root.as_ptr()));

    // Change to  working directory
    let cwd = CString::new(config.working_directory.to_str().unwrap()).unwrap();
    check_syscall!(chdir(cwd.as_ptr()));
}

unsafe fn exec_child(config: &SandboxConfiguration) -> ! {
    assert!(config.executable.exists(), "Executable doesn't exist inside the sandbox chroot. Perhaps you need to mount some directories?");
    let exe = CString::new(config.executable.to_str().unwrap()).unwrap();

    // Build args array
    let args: Vec<CString> = config
        .args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let mut argv: Vec<*const c_char> = args.iter().map(|s| s.as_ptr()).collect();
    argv.insert(0, exe.as_ptr()); // set executable name
    argv.push(null()); // null terminate

    // Build environment array
    let mut env: Vec<CString> = Vec::new();
    for (variable, value) in &config.env {
        env.push(CString::new(format!("{}={}", variable, value)).unwrap());
    }
    let mut envp: Vec<*const c_char> = env.iter().map(|s| s.as_ptr()).collect();
    envp.push(null()); // null terminate

    check_syscall!(execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr()));

    unreachable!();
}

/// Setup the Syscall filter
unsafe fn setup_syscall_filter(config: &SandboxConfiguration) {
    if let Some(syscall_filter) = &config.syscall_filter {
        let mut filter = SeccompFilter::new(syscall_filter.default_action);
        for (syscall, action) in &syscall_filter.rules {
            filter.filter(syscall, *action);
        }
        filter.load();
    }
}

/// Setup the sandbox filesystem
unsafe fn setup_filesystem(config: &SandboxConfiguration, sandbox_path: &Path) {
    // Create the sandbox dir and mount a tmpfs in it
    mount("tmpfs", &sandbox_path, "tmpfs", 0, "size=256M");

    // Create /dev
    let dev = sandbox_path.join("dev");
    fs::create_dir_all(&dev).unwrap();

    make_dev(&dev.join("null"), 1, 3);
    make_dev(&dev.join("zero"), 1, 5);
    make_dev(&dev.join("random"), 1, 8);
    make_dev(&dev.join("urandom"), 1, 9);

    // Mount /tmp and /dev/shm
    if config.mount_tmpfs {
        mount("tmpfs", &sandbox_path.join("tmp"), "tmpfs", 0, "size=256M");
        mount(
            "tmpfs",
            &sandbox_path.join("dev/shm"),
            "tmpfs",
            0,
            "size=256M",
        );
    }

    // bind mount the readable directories into the sandbox
    for dir in &config.mount_paths {
        mount_dir(dir, sandbox_path);
    }

    // Remount tmpfs read only
    mount("tmpfs", &sandbox_path, "tmpfs", MS_REMOUNT | MS_RDONLY, "");
}

/// Setup stdio file redirection
unsafe fn setup_io_redirection(config: &SandboxConfiguration) {
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
unsafe fn setup_resource_limits(config: &SandboxConfiguration) {
    if let Some(memory_limit) = config.memory_limit {
        check_syscall!(set_resource_limit(RLIMIT_AS, memory_limit * 1_000_000));
    }

    if let Some(time_limit) = config.time_limit {
        check_syscall!(set_resource_limit(RLIMIT_CPU, time_limit));
    }
}

/// Create a device
unsafe fn make_dev(path: &Path, major: u32, minor: u32) {
    trace!(
        "Make device {:?} with major = {}, minor = {}",
        path,
        major,
        minor
    );
    let dev = CString::new(path.to_str().unwrap()).unwrap();
    check_syscall!(mknod(
        dev.as_ptr(),
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
        makedev(major, minor)
    ));
}

/// Mount a directory inside the sandbox
unsafe fn mount_dir(dir: &DirectoryMount, sandbox_dir: &Path) {
    trace!("Mount {:?}", dir);

    let prepare_dir = |dir: &Path| {
        // Join destination with the sandbox directory
        let target = sandbox_dir.join(dir.strip_prefix("/").unwrap());

        // Create all the required directories in the destination
        std::fs::create_dir_all(&target).unwrap();

        // Convert to C string
        target
    };

    match dir {
        DirectoryMount::Bind(bind) => {
            assert_ne!(bind.target, Path::new("/"));

            let target = prepare_dir(&bind.target);

            mount(
                bind.source.to_str().unwrap(),
                &target,
                "",
                MS_BIND | MS_REC,
                "",
            );

            if !bind.writable {
                mount("", &target, "", MS_REMOUNT | MS_RDONLY | MS_BIND, "");
            }
        }
        DirectoryMount::Tmpfs(path) => {
            mount("tmpfs", &prepare_dir(path), "tmpfs", 0, "");
        }
    }
}

/// Wrapper around mount system call
unsafe fn mount(source: &str, target: &Path, fstype: &str, options: u64, data: &str) {
    fs::create_dir_all(target).unwrap();

    trace!(
        "mount({}, {:?}, {}, {}, {})",
        source,
        target,
        fstype,
        options,
        data
    );
    let source = CString::new(source).unwrap();
    let target = CString::new(target.to_str().unwrap()).unwrap();
    let fstype = CString::new(fstype).unwrap();
    let data = CString::new(data).unwrap();

    check_syscall!(libc::mount(
        source.as_ptr(),
        target.as_ptr(),
        fstype.as_ptr(),
        options,
        data.as_ptr() as *const c_void,
    ));
}

/// Utility function to set resource limit
unsafe fn set_resource_limit(resource: u32, limit: u64) -> i32 {
    let r_limit = rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };

    setrlimit(resource, &r_limit)
}
