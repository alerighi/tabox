// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use super::util::*;
use crate::configuration::SandboxConfigurationBuilder;
use crate::result::ExitStatus;

#[test]
fn test_memory_limit_ok() {
    let program = r#"
       #include <stdlib.h>
       int main() { int s = 200 * 1000000; char *m = malloc(s); for (int i = 0; i < s; i++) m[i] = i; return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.memory_limit(256);

    let result = exec(program, &mut config, "");

    assert!(result.result.resource_usage.memory_usage > 200_000_000);
    assert!(result.result.status.is_success());
}

#[test]
fn test_memory_limit_exceeded() {
    let program = r#"
       #include <stdlib.h>
       int main() { int s = 256 * 1000000; char *m = malloc(s); for (int i = 0; i < s; i++) m[i] = i; return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.memory_limit(256);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(11));
}

#[test]
fn test_time_limit() {
    let program = r#"
       #include <stdio.h>
       int main() { while(1); }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.time_limit(1);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(9));
}
