use seccomp_sys::*;
use std::ffi::CString;
use crate::SyscallFilterAction;

impl SyscallFilterAction {
    fn to_seccomp_param(&self) -> u32 {
        match self {
            SyscallFilterAction::Allow => SCMP_ACT_ALLOW,
            SyscallFilterAction::Kill => SCMP_ACT_KILL,
            SyscallFilterAction::Errno(errno) => SCMP_ACT_ERRNO(*errno),
        }
    }
}

pub struct SeccompFilter {
    ctx: *mut scmp_filter_ctx,
}

impl SeccompFilter {
    /// Create a new filter
    pub fn new(default_action: SyscallFilterAction) -> SeccompFilter {
        let ctx = unsafe { seccomp_init(default_action.to_seccomp_param()) };
        if ctx.is_null() {
            panic!("Error initializing seccomp filter");
        }
        SeccompFilter {
            ctx,
        }
    }

    /// Allow a syscall
    pub fn filter(&mut self, name: &str, action: SyscallFilterAction) {
        let syscall_name = CString::new(name).unwrap();
        unsafe {
            let syscall_num = check_syscall!(seccomp_syscall_resolve_name(syscall_name.as_ptr()));
            check_syscall!(seccomp_rule_add(self.ctx, action.to_seccomp_param(), syscall_num, 0));
        }
    }

    /// Load the specified filter
    pub fn load(&self) {
        unsafe {
            check_syscall!(seccomp_load(self.ctx));
        }
    }
}

impl Drop for SeccompFilter {
    fn drop(&mut self) {
        unsafe {
            seccomp_release(self.ctx);
        }
    }
}