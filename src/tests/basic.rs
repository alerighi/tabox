// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use super::util::*;
use crate::configuration::SandboxConfigurationBuilder;
use crate::result::ExitStatus;

#[test]
fn test_ok_program() {
    let program = r#"
       #include <stdio.h>
       int main() { printf("hello, world!"); fprintf(stderr, "error"); return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.time_limit(1);
    config.memory_limit(256);

    let result = exec(program, &mut config, "");

    assert!(result.result.status.is_success());
    assert_eq!(result.stdout, "hello, world!");
    assert_eq!(result.stderr, "error");
}

#[test]
fn test_signal_program() {
    let program = r#"
       #include <stdio.h>
       int main() { int *ptr = NULL; *ptr = 42; return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(11));
}

#[test]
fn test_env() {
    let program = r#"
        #include <stdio.h>
        #include <stdlib.h>
        int main() { printf("%s", getenv("VAR")); return 0; }
    "#;

    let mut config = SandboxConfigurationBuilder::default();
    config.env("VAR", "42");
    let result = exec(program, &mut config, "");
    assert_eq!(result.result.status, ExitStatus::ExitCode(0));
    assert_eq!(result.stdout, "42");
}
