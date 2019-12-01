// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

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
