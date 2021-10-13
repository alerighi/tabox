// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! [![Docs]( https://docs.rs/tabox/badge.svg)]( https://docs.rs/tmbox)
//! [![crates.io](https://img.shields.io/crates/v/tabox.svg)](https://crates.io/crates/tabox)
//!
//! A sandbox for task-maker and TuringArena
//!
//! ### What does it do
//! tabox allows you to do two things:
//! - launch a process in a secure environment, where it cannot damage the existing machine
//! - measure and limit the resource (cpu time, memory) usage of the process

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

pub mod configuration;
pub mod result;
pub mod syscall_filter;

mod util;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

/// The sandbox implementation
#[cfg(target_os = "linux")]
pub type SandboxImplementation = linux::LinuxSandbox;

#[cfg(target_os = "macos")]
pub type SandboxImplementation = macos::MacOSSandbox;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("TAbox not supported on your operating system");

#[cfg(test)]
mod tests;

/// Convenience result type
pub type Result<T> = std::result::Result<T, anyhow::Error>;

/// A trait that represents a Sandbox
pub trait Sandbox {
    /// Execute the sandbox
    fn run(config: configuration::SandboxConfiguration) -> Result<Self>
    where
        Self: Sized;

    /// Wait the process to terminate, giving back the execution result
    fn wait(self) -> Result<result::SandboxExecutionResult>;

    /// Return true if the sandbox implementation is secure
    fn is_secure() -> bool;
}
