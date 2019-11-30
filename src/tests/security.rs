// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use super::util::*;
use crate::configuration::SandboxConfigurationBuilder;
use crate::result::ExitStatus;
use crate::syscall_filter::{SyscallFilter, SyscallFilterAction};

#[test]
fn test_seccomp_filter() {
    let program = r#"
       #include <unistd.h>
       int main() { getuid(); return 0; }
    "#;

    let mut filter = SyscallFilter::default();
    filter.
        default_action(SyscallFilterAction::Allow)
        .add_rule("getuid", SyscallFilterAction::Kill);

    let mut config = SandboxConfigurationBuilder::default();
    config
        .memory_limit(256)
        .syscall_filter(filter);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(31));
}

#[test]
fn test_fork_block() {
    let program = r#"
       #include <unistd.h>
       int main() { fork(); return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();

    config.syscall_filter(SyscallFilter::build(false, false));

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(31));
}

#[test]
fn test_chmod_block() {
    let program = r#"
       #include <fcntl.h>
       int main() { chmod("file", 777); return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();

    config.syscall_filter(SyscallFilter::build(false, false));

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(31));
}