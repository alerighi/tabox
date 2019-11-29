use crate::{Result, Sandbox, SandboxConfiguration, SandboxExecutionResult};
use std::error::Error;

pub struct MacOSSandbox {}

impl Sandbox for MacOSSandbox {
    fn run(config: SandboxConfiguration) -> Result<Self> {
        unimplemented!()
    }

    fn wait(self) -> Result<SandboxExecutionResult> {
        unimplemented!()
    }

    fn is_secure() -> bool {
        false
    }
}
