// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::util::*;
use crate::configuration::SandboxConfiguration;
use crate::result::ExitStatus;

#[test]
fn test_memory_limit_ok() {
    let program = r#"
       #include <stdlib.h>
       int main() { int s = 200 * 1000000; char *m = malloc(s); for (int i = 0; i < s; i++) m[i] = i; return 0; }
    "#;

    let mut config = SandboxConfiguration::default();
    config.memory_limit(256 * 1_000_000);

    let result = exec(program, &mut config, "");

    assert!(result.result.resource_usage.memory_usage > 200_000_000);
    assert!(result.result.status.success());
}

#[test]
fn test_memory_limit_exceeded() {
    let program = r#"
       #include <stdlib.h>
       int main() { int s = 512 * 1000000; char *m = malloc(s); for (int i = 0; i < s; i++) m[i] = i; return 0; }
    "#;

    let mut config = SandboxConfiguration::default();
    config.memory_limit(256 * 1_000_000);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(11));
}

const STACK_LIMIT_TEST_SRC: &str = r#"
// each call consumes ~8KiB
int f(int n) {
    if (n == 0) return 123;
    char data[8*1024];
    int x = f(n - 1);
    for (int i = 0; i < 8*1024; i++) {
        data[i] = (i + x) & 0xff;
    }
    return data[123] + x;
}
int main() {
    // ~10*1024*8KiB = ~80MiB
    f(10*1024);
}
"#;

#[test]
fn test_stack_limit_ok() {
    let mut config = SandboxConfiguration::default();
    config
        .memory_limit(100 * 1_000_000)
        .stack_limit(100 * 1_000_000);

    let result = exec(STACK_LIMIT_TEST_SRC, &mut config, "");

    assert!(result.result.resource_usage.memory_usage > 80_000_000);
    assert!(result.result.status.success());
}

#[test]
fn test_stack_limit_default() {
    let mut config = SandboxConfiguration::default();
    config.memory_limit(100 * 1_000_000);

    let result = exec(STACK_LIMIT_TEST_SRC, &mut config, "");

    assert!(result.result.resource_usage.memory_usage > 80_000_000);
    assert!(result.result.status.success());
}

#[test]
fn test_stack_limit_exceeded() {
    let mut config = SandboxConfiguration::default();
    config
        .memory_limit(60 * 1_000_000)
        .stack_limit(60 * 1_000_000);

    let result = exec(STACK_LIMIT_TEST_SRC, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(11));
}

#[test]
fn test_stack_limit_exceeded_default() {
    let mut config = SandboxConfiguration::default();
    config.memory_limit(60 * 1_000_000);

    let result = exec(STACK_LIMIT_TEST_SRC, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Signal(11));
}

#[test]
fn test_time_limit_exceeded() {
    let program = r#"
       #include <stdio.h>
       int main() { while(1); }
    "#;

    let mut config = SandboxConfiguration::default();
    config.time_limit(1);

    let result = exec(program, &mut config, "");

    #[cfg(not(target_os = "linux"))]
    assert_eq!(result.result.status, ExitStatus::Signal(24));

    // For whatever reason Linux kills process with SIGKILL, instead of SIGXCPU
    #[cfg(target_os = "linux")]
    assert_eq!(result.result.status, ExitStatus::Signal(9));
}

#[test]
fn test_time_usage() {
    let program = r#"
       #include <time.h>
       int main() { for (int t = time(NULL); t + 2 >= time(NULL); ); return 0; }
    "#;

    let mut config = SandboxConfiguration::default();
    config.time_limit(20);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::ExitCode(0));
    assert!(result.result.resource_usage.user_cpu_time >= 1.9);
    assert!(result.result.resource_usage.user_cpu_time <= 3.1);
}

#[test]
fn test_wall_time_usage() {
    let program = r#"
       #include <unistd.h>
       int main() { sleep(2); return 0; }
    "#;

    let mut config = SandboxConfiguration::default();
    config.time_limit(1).wall_time_limit(4);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::ExitCode(0));
    assert!(
        result.result.resource_usage.wall_time_usage > 2.0
            && result.result.resource_usage.wall_time_usage < 2.1
    )
}

#[test]
fn test_wall_time_exceeded() {
    let program = r#"
       #include <unistd.h>
       int main() { sleep(10); return 0; }
    "#;

    let mut config = SandboxConfiguration::default();
    config.time_limit(1).wall_time_limit(1);

    let result = exec(program, &mut config, "");

    assert_eq!(result.result.status, ExitStatus::Killed);
    assert!(
        result.result.resource_usage.wall_time_usage > 1.0
            && result.result.resource_usage.wall_time_usage < 1.1
    )
}
