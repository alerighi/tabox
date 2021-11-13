use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::configuration::SandboxConfiguration;
use crate::result::{ExitStatus, ResourceUsage};
use crate::Result;

// MacOS libc crate seems to have miss this function... so I declare it
extern "C" {
    fn wait4(
        pid: libc::pid_t,
        status: *mut libc::c_int,
        options: libc::c_int,
        rusage: *mut libc::rusage,
    ) -> libc::pid_t;
}

/// Setup the resource limits
pub fn setup_resource_limits(config: &SandboxConfiguration) -> Result<()> {
    // on macOS Montmery this seems to fail for no reason
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(memory_limit) = config.memory_limit {
            set_resource_limit(libc::RLIMIT_AS, memory_limit).context("Failed to set RLIMIT_AS")?;
        }
    }

    if let Some(stack_limit) = config.stack_limit {
        set_resource_limit(libc::RLIMIT_STACK, stack_limit)
            .context("Failed to set RLIMIT_STACK")?;
    } else {
        set_resource_limit(libc::RLIMIT_STACK, libc::RLIM_INFINITY)
            .context("Failed to set RLIMIT_STACK")?;
    }

    if let Some(time_limit) = config.time_limit {
        set_resource_limit(libc::RLIMIT_CPU, time_limit).context("Failed to set RLIMIT_CPU")?;
    }

    // No core dumps
    set_resource_limit(libc::RLIMIT_CORE, 0).context("Failed to set RLIMIT_CORE")
}

#[cfg(target_env = "gnu")]
type Resource = u32;

#[cfg(not(target_env = "gnu"))]
type Resource = i32;

/// Utility function to set a resource limit
fn set_resource_limit(resource: Resource, limit: u64) -> Result<()> {
    unsafe {
        let rlim = limit as libc::rlim_t;
        let mut current_limit: libc::rlimit = std::mem::zeroed();

        let code = libc::getrlimit(resource, &mut current_limit);
        if code < 0 {
            panic!("getrlimit() error: {}", code);
        }

        let new_limit = libc::rlimit {
            // avoid increasing over the hard limit. You need to be superuser for that!
            rlim_cur: if rlim < current_limit.rlim_max {
                rlim
            } else {
                current_limit.rlim_max
            },
            rlim_max: if rlim < current_limit.rlim_max {
                rlim
            } else {
                current_limit.rlim_max
            },
        };

        let code = libc::setrlimit(resource, &new_limit);
        if code < 0 {
            bail!("Error calling setrlimit(): {}", strerror());
        } else {
            Ok(())
        }
    }
}

/// Wait for child completion, returning a WaitStatus and ResourceUsage
pub fn wait(pid: libc::pid_t) -> Result<(ExitStatus, ResourceUsage)> {
    let mut status = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

    if unsafe { wait4(pid, &mut status, 0, &mut rusage) } != pid {
        bail!("Error waiting for child completion: {}", strerror());
    };

    let status = unsafe {
        if libc::WIFEXITED(status) {
            ExitStatus::ExitCode(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            ExitStatus::Signal(libc::WTERMSIG(status))
        } else {
            bail!("Child terminated with unknown status");
        }
    };

    let resource_usage = ResourceUsage {
        memory_usage: rusage.ru_maxrss as u64 * 1024,
        user_cpu_time: rusage.ru_utime.tv_usec as f64 / 1_000_000.0 + rusage.ru_utime.tv_sec as f64,
        system_cpu_time: rusage.ru_stime.tv_usec as f64 / 1_000_000.0
            + rusage.ru_stime.tv_sec as f64,
        wall_time_usage: 0.0,
    };

    Ok((status, resource_usage))
}

pub fn start_wall_time_watcher(limit: u64, child_pid: i32, killed: Arc<AtomicBool>) -> Result<()> {
    std::thread::Builder::new()
        .name("Wall time watcher".into())
        .spawn(move || {
            std::thread::sleep(Duration::new(limit, 0));

            // Kill process if it didn't terminate in wall limit
            kill(Pid::from_raw(child_pid), Signal::SIGKILL)
                .expect("Error killing child due to wall limit exceeded");

            killed.store(true, Ordering::SeqCst);
        })
        .context("Failed to spawn Wall time watcher thread")?;
    Ok(())
}

/// Read the error from errno and using `libc::strerror` obtain a string representation of it.
pub fn strerror() -> String {
    unsafe {
        let err = libc::strerror(nix::errno::errno());
        let str = std::ffi::CStr::from_ptr(std::mem::transmute(err));
        str.to_str().unwrap().into()
    }
}

#[cfg(unix)]
mod unix {
    use std::os::raw::c_char;

    extern "C" {
        /// http://man7.org/linux/man-pages/man3/strsignal.3.html
        pub fn strsignal(signal: i32) -> *mut c_char;
    }
}

/// Returns a string with the text representation of the signal, `None` if it's not available.
pub fn strsignal(signal: i32) -> Option<String> {
    #[cfg(unix)]
    {
        use nix::NixPath;
        unsafe {
            let cstr = std::ffi::CStr::from_ptr(unix::strsignal(signal));
            if cstr.is_empty() {
                None
            } else {
                Some(cstr.to_string_lossy().to_string())
            }
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}
