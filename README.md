<!-- 
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
SPDX-License-Identifier: MPL-2.0
-->

# tabox

[![Docs]( https://docs.rs/tabox/badge.svg)]( https://docs.rs/tabox)
[![crates.io](https://img.shields.io/crates/v/tabox.svg)](https://crates.io/crates/tabox)

A minimal program to securely execute untrusted executables in a sandboxed environment.

Featres:
- measure and limit accurately the usage of the following resources:
	* CPU time in nanoseconds (both user, system)
	* memory usage (maximum residente set size - RSS) in bytes
	* wall time
- doesn't require root privileges (altough it requires user namespaces enabled, something that some distributions disable by default)
- dedicated filesystem for the sandbox with the possibility to bind-mount directories on the local filesyste, both read-only and read-write
- works also on macOS, altough in that system no real sandboxing is done and some features are not available (e.g. bind mounts)

This sandbox is currently used by [task-maker-rust](https://github.com/edomora97/task-maker-rust)
to securely execute user submissions. 

License: MPL-2.0
