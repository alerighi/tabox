/// Macro to check the return code of a system call, wrapping it in an unsafe block.
/// If the return code is negative it's considered a failure
/// and the program panics.
macro_rules! check_syscall {
    ($call:expr) => {{
        #[allow(unused_unsafe)]
        let result = unsafe { $call };
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

#[cfg(target_os = "linux")]
type Resource = u32;

#[cfg(target_os = "macos")]
type Resource = i32;

/// Utility function to set a resource limit
pub fn set_resource_limit(resource: Resource, limit: u64) {
    let r_limit = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };

    check_syscall!(libc::setrlimit(resource, &r_limit));
}
