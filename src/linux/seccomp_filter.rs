// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use std::ffi::CString;

use anyhow::bail;

use crate::syscall_filter::SyscallFilterAction;
use crate::util::strerror;
use crate::Result;

impl SyscallFilterAction {
    /// Transform the Action to the correct seccomp parameter
    fn to_seccomp_param(self) -> u32 {
        match self {
            SyscallFilterAction::Allow => seccomp_sys::SCMP_ACT_ALLOW,
            SyscallFilterAction::Kill => seccomp_sys::SCMP_ACT_KILL,
            SyscallFilterAction::Errno(errno) => seccomp_sys::SCMP_ACT_ERRNO(errno),
        }
    }
}

/// Wrapper of a libseccomp filter object
pub struct SeccompFilter {
    ctx: *mut seccomp_sys::scmp_filter_ctx,
}

impl SeccompFilter {
    /// Create a new filter
    pub fn new(default_action: SyscallFilterAction) -> Result<SeccompFilter> {
        let ctx = unsafe { seccomp_sys::seccomp_init(default_action.to_seccomp_param()) };
        if ctx.is_null() {
            bail!("seccomp_init() error: {}", strerror())
        } else {
            Ok(SeccompFilter { ctx })
        }
    }

    /// Allow a syscall
    pub fn filter(&mut self, name: &str, action: SyscallFilterAction) -> Result<()> {
        debug!("Add rule {} {:?}", name, action);
        let syscall_name = CString::new(name).unwrap();
        let syscall_num =
            unsafe { seccomp_sys::seccomp_syscall_resolve_name(syscall_name.as_ptr()) };
        if syscall_num == seccomp_sys::__NR_SCMP_ERROR {
            bail!(
                "Error calling seccomp_syscall_resolve_name: unknown system call: {}",
                name
            );
        }
        if unsafe {
            seccomp_sys::seccomp_rule_add(self.ctx, action.to_seccomp_param(), syscall_num, 0)
        } < 0
        {
            bail!("Error calling seccomp_rule_add(): {}", strerror())
        } else {
            Ok(())
        }
    }

    /// Load the specified filter
    pub fn load(&self) -> Result<()> {
        if unsafe { seccomp_sys::seccomp_load(self.ctx) } < 0 {
            bail!("Error calling seccomp_load(): {}", strerror())
        } else {
            Ok(())
        }
    }
}

impl Drop for SeccompFilter {
    fn drop(&mut self) {
        unsafe {
            seccomp_sys::seccomp_release(self.ctx);
        }
    }
}
