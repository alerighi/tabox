extern crate seccomp_sys;
extern crate errno;

use crate::{Sandbox, SandboxExecutionResult, SandboxConfiguration, ResourceUsage, Result};
use tempdir::TempDir;
use std::fs::File;
use std::path::PathBuf;
use std::ffi::CString;
use libc::*;
use std::ptr::null;
use std::os::unix::io::IntoRawFd;

macro_rules! check_syscall {
    ($call:expr) => {
        {
            let result = $call;
            trace!("{} = {}", stringify!($call), result);
            if result < 0 {
                panic!("{} failed with exit code {} ({})", stringify!($call), result, errno::errno());
            }
            result
        }
    }
}

mod seccomp_filter;

use seccomp_filter::*;

pub struct LinuxSandbox {
    config: SandboxConfiguration,
    tempdir: TempDir,
    child_pid: pid_t,
}

impl Sandbox for LinuxSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        trace!("Run LinuxSandbox with config {:?}", config);
        let mut sandbox = LinuxSandbox {
            config,
            tempdir: TempDir::new("tabox")?,
            child_pid: 0,
        };
        unsafe { sandbox.start_process() }
        Ok(sandbox)
    }

    fn wait(self) -> Result<SandboxExecutionResult> {
        trace!("Sandbox (dir = {:?}) waiting for child (PID = {}) completion", self.tempdir, self.child_pid);
        unsafe {
            let mut status = 0;
            let mut rusage: rusage = std::mem::zeroed();
            wait4(self.child_pid, &mut status, 0, &mut rusage);
            Ok(SandboxExecutionResult {
                return_code: if WIFEXITED(status) { Some(WEXITSTATUS(status)) } else { None },
                signal: if WIFSIGNALED(status) { Some(WTERMSIG(status)) } else { None },
                resource_usage: ResourceUsage {
                    memory_usage: rusage.ru_maxrss as usize * 1024,
                    user_cpu_time: rusage.ru_utime.tv_usec as f64 / 1_000_000.0 + rusage.ru_utime.tv_sec as f64,
                    system_cpu_time: rusage.ru_stime.tv_usec as f64 / 1_000_000.0 + rusage.ru_stime.tv_sec as f64,
                },
            })
        }
    }

    fn is_secure() -> bool {
        true
    }
}

impl LinuxSandbox {

    /// Forks a sandbox child
    unsafe fn start_process(&mut self) {
        self.child_pid = match check_syscall!(fork()) {
            0 => self.child(),
            pid => pid,
        };
        trace!("Sandbox (dir = {:?}) forked PID = {}", self.tempdir, self.child_pid);
    }

    /// Mount a directory inside the sandbox
    unsafe fn mount_dir(&self, dir: &PathBuf) {
        let dest = self.tempdir.path().join(dir.strip_prefix("/").unwrap());

        trace!("Mount {:?} to {:?}", dir, dest);

        // create all the required directories in the destination
        std::fs::create_dir_all(&dest).unwrap();

        let src = CString::new(dir.to_str().unwrap()).unwrap();
        let dest = CString::new(dest.to_str().unwrap()).unwrap();

        check_syscall!(mount(src.as_ptr(), dest.as_ptr(), null(), MS_BIND | MS_REC, null()));
    }

    unsafe fn child(&self) -> ! {
        let sandbox_path = self.tempdir.path();

        // uid/gid from outside the sandbox
        let uid = getuid();
        let gid = getgid();

        // enter unshared namespace
        check_syscall!(unshare(CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS));

        // map current uid/gid to root/root inside the sandbox
        std::fs::write("/proc/self/setgroups", "deny").unwrap();
        std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid)).unwrap();
        std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid)).unwrap();

        // I'm now root inside the sandbox
        check_syscall!(setuid(0));
        check_syscall!(setgid(0));

        // bind mount the readable directories into the sandbox
        for dir in &self.config.mount_paths {
            self.mount_dir(dir);
        }

        // chroot into the sandbox
        check_syscall!(chroot(CString::new(sandbox_path.to_str().unwrap()).unwrap().as_ptr()));

        // change to the working directory
        check_syscall!(chdir(CString::new(self.config.working_directory.to_str().unwrap()).unwrap().as_ptr()));

        assert_eq!(self.config.executable.exists(), true, "Executable doesn't exist inside the sandbox chroot. Perhaps you need to mount some directories?");

        // set resource limits
        if let Some(memory_limit) = self.config.memory_limit {
            check_syscall!(set_resource_limit(RLIMIT_AS, memory_limit * 1_000_000));
        }

        if let Some(time_limit) = self.config.time_limit {
            check_syscall!(set_resource_limit(RLIMIT_CPU, time_limit));
        }

        // setup io redirection
        if let Some(stdin) = &self.config.stdin {
            let file = File::open(stdin).unwrap();
            check_syscall!(dup2(file.into_raw_fd(), 0));
        }

        if let Some(stdout) = &self.config.stdout {
            let file = File::create(stdout).unwrap();
            check_syscall!(dup2(file.into_raw_fd(), 1));
        }

        if let Some(stderr) = &self.config.stderr {
            let file = File::create(stderr).unwrap();
            check_syscall!(dup2(file.into_raw_fd(), 2));
        }

        // setup syscall filter
        if let Some(syscall_filter) = &self.config.syscall_filter {
            let mut filter = SeccompFilter::new(Action::Allow);
            for syscall in syscall_filter {
                filter.filter(syscall, Action::Kill);
            }
            filter.load();
        }

        let exe = CString::new(self.config.executable.to_str().unwrap()).unwrap();

        // build args array
        let args: Vec<CString> = self.config.args.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
        let mut argv: Vec<*const c_char> = args.iter().map(|s| s.as_ptr()).collect();
        argv.insert(0, exe.as_ptr()); // set executable name
        argv.push(null());  // null terminate

        // build environment array
        let env: Vec<CString> = self.config.env.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
        let mut envp: Vec<*const c_char> = env.iter().map(|s| s.as_ptr()).collect();
        envp.push(null()); // null terminate

        // exec the sandbox
        check_syscall!(execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr()));

        // should never be reached!
        panic!("Something went seriously wrong");
    }

}

/// Utility function to set resource limit
unsafe fn set_resource_limit(resource: u32, limit: u64) -> i32 {
    let r_limit = rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };

    setrlimit(resource, &r_limit)
}
