// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use super::util::*;
use crate::{ExitStatus, SandboxConfigurationBuilder, SyscallFilter, SyscallFilterAction};

#[test]
fn test_seccomp_filter() {
    let program = r#"
       #include <unistd.h>
       int main() { getuid(); return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.memory_limit(256);
    config.syscall_filter(SyscallFilter {
        default_action: SyscallFilterAction::Allow,
        rules: vec![("getuid".to_string(), SyscallFilterAction::Kill)],
    });

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(31));
}
