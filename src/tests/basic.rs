use super::util::*;
use crate::{ExitStatus, SandboxConfigurationBuilder};

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
