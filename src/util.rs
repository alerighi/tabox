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
    if let Some(memory_limit) = config.memory_limit {
        set_resource_limit(libc::RLIMIT_AS, memory_limit)?;
    }

    if let Some(time_limit) = config.time_limit {
        set_resource_limit(libc::RLIMIT_CPU, time_limit)?;
    }

    // No core dumps
    set_resource_limit(libc::RLIMIT_CORE, 0)
}

#[cfg(target_os = "linux")]
type Resource = u32;

#[cfg(target_os = "macos")]
type Resource = i32;

/// Utility function to set a resource limit
fn set_resource_limit(resource: Resource, limit: u64) -> Result<()> {
    let r_limit = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };

    if unsafe { libc::setrlimit(resource, &r_limit) } < 0 {
        Err(failure::err_msg("Error calling setrlimit()"))
    } else {
        Ok(())
    }
}

/// Wait for child completion, returning a WaitStatus and ResourceUsage
pub fn wait(pid: libc::pid_t) -> Result<(ExitStatus, ResourceUsage)> {
    let mut status = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

    if unsafe { wait4(pid, &mut status, 0, &mut rusage) } != pid {
        return Err(failure::err_msg("Error waiting for child completion"));
    };

    let status = unsafe {
        if libc::WIFEXITED(status) {
            ExitStatus::ExitCode(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            ExitStatus::Signal(libc::WTERMSIG(status))
        } else {
            return Err(failure::err_msg("Child terminated with unknown status"));
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
