// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};

/// System call filter action
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum SyscallFilterAction {
    /// Allow all system calls
    Allow,

    /// Kill the process
    Kill,

    /// Return this errno
    Errno(u32),
}

/// Syscall filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallFilter {
    /// Default action to execute
    pub default_action: SyscallFilterAction,

    /// Sandbox filter rules in the form of (syscall_name, action)
    pub rules: Vec<(String, SyscallFilterAction)>,
}

impl Default for SyscallFilter {
    fn default() -> Self {
        SyscallFilter {
            default_action: SyscallFilterAction::Kill,
            rules: Vec::new(),
        }
    }
}

impl SyscallFilter {
    /// Build a filter that blocks most dangerous syscalls
    pub fn build(multiprocess: bool, chmod: bool) -> Self {
        let mut filter = SyscallFilter::default();
        filter.default_action(SyscallFilterAction::Allow);
        if !multiprocess {
            filter.add_rule("fork", SyscallFilterAction::Kill);
            filter.add_rule("vfork", SyscallFilterAction::Kill);
            filter.add_rule("clone", SyscallFilterAction::Kill);
        }
        if !chmod {
            filter.add_rule("chmod", SyscallFilterAction::Kill);
            filter.add_rule("fchmod", SyscallFilterAction::Kill);
            filter.add_rule("fchmodat", SyscallFilterAction::Kill);
        }
        filter
    }

    /// Set the default filter action
    pub fn default_action(&mut self, action: SyscallFilterAction) -> &mut Self {
        self.default_action = action;
        self
    }

    /// Add a rule to the filter
    pub fn add_rule<S: Into<String>>(
        &mut self,
        syscall: S,
        action: SyscallFilterAction,
    ) -> &mut Self {
        self.rules.push((syscall.into(), action));
        self
    }
}
