// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::syscall_filter::SyscallFilterAction;
use seccomp_sys::*;
use std::ffi::CString;

impl SyscallFilterAction {
    /// Transform the Action to the correct seccomp parameter
    fn to_seccomp_param(self) -> u32 {
        match self {
            SyscallFilterAction::Allow => SCMP_ACT_ALLOW,
            SyscallFilterAction::Kill => SCMP_ACT_KILL,
            SyscallFilterAction::Errno(errno) => SCMP_ACT_ERRNO(errno),
        }
    }
}

/// Wrapper of a libseccomp filter object
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
        SeccompFilter { ctx }
    }

    /// Allow a syscall
    pub fn filter(&mut self, name: &str, action: SyscallFilterAction) {
        debug!("Add rule {} {:?}", name, action);
        let syscall_name = CString::new(name).unwrap();
        unsafe {
            let syscall_num = check_syscall!(seccomp_syscall_resolve_name(syscall_name.as_ptr()));
            check_syscall!(seccomp_rule_add(
                self.ctx,
                action.to_seccomp_param(),
                syscall_num,
                0
            ));
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
