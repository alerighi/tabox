// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

#[macro_use]
extern crate log;

use std::path::PathBuf;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use tabox::configuration::SandboxConfiguration;
use tabox::syscall_filter::SyscallFilter;
use tabox::Result;
use tabox::{Sandbox, SandboxImplementation};

/// Command line arguments of the program
#[derive(Debug, Clone, Serialize, Deserialize, StructOpt)]
#[structopt(
    name = "tabox",
    about = "Execute code in a secure sandbox",
    setting = structopt::clap::AppSettings::ColoredHelp)
]
struct Args {
    /// Time limit for the execution
    #[structopt(long, short)]
    time_limit: Option<u64>,

    /// Memory limit fot the execution, in megabytes
    #[structopt(long, short)]
    memory_limit: Option<u64>,

    /// Absolute path of the executable
    executable: PathBuf,

    /// Arguments to pass to the executable
    args: Vec<String>,

    /// Environment to pass to the executable
    #[structopt(long)]
    env: Vec<String>,

    /// Mount paths inside the sandbox
    ///
    /// Syntax: --mount=local/path,sandbox/path,rw where only the first argument is required.
    /// If only 2 arguments are supplied they follow this semantics:
    ///
    /// - --mount=local,rw (if the second is rw, the sandbox path is the same as the local one)
    /// - --mount=local,sandbox (if the second is not rw, it is assumed to be ro)
    ///
    /// The only valid options for the last argument are: ro (read-only mount) or rw (read-write
    /// mount). By default the mount is read-only.
    #[structopt(long = "mount")]
    mount: Vec<String>,

    /// Working directory for the process. Of course must be a directory mounted
    #[structopt(long)]
    working_directory: Option<PathBuf>,

    /// Allow chmod
    #[structopt(long)]
    allow_chmod: bool,

    /// Allow process/thread creation in the sandbox
    #[structopt(long)]
    allow_multiprocess: bool,

    /// Redirect stdin from this file
    #[structopt(long, short = "i")]
    stdin: Option<PathBuf>,

    /// Redirect stdout from this file
    #[structopt(long, short = "o")]
    stdout: Option<PathBuf>,

    /// Redirect stderr from this file
    #[structopt(long, short = "e")]
    stderr: Option<PathBuf>,

    /// Allow insecure sandbox
    #[structopt(long)]
    allow_insecure: bool,

    /// output in JSON format
    #[structopt(long, short)]
    json: bool,

    /// Mount a tmpfs in /tmp and /dev/shm
    #[structopt(long)]
    mount_tmpfs: bool,

    /// Wall time limit
    #[structopt(long)]
    wall_limit: Option<u64>,

    /// Run on the specified cpu core
    #[structopt(long)]
    cpu_core: Option<usize>,

    /// UID of the user inside the sandbox
    #[structopt(long, default_value = "0")]
    pub uid: usize,

    /// GID of the user inside the sandbox
    #[structopt(long, default_value = "0")]
    pub gid: usize,

    /// Mount /proc
    #[structopt(long)]
    pub mount_proc: bool,
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::from_args();

    if !SandboxImplementation::is_secure() && !args.allow_insecure {
        eprintln!("Your platform doesn't support a secure sandbox!");
        eprintln!("Run with --allow-insecure if you really want to execute it anyway");
        std::process::exit(1);
    }

    let mut config = SandboxConfiguration::default();

    config
        .executable(args.executable)
        .mount_tmpfs(args.mount_tmpfs)
        .uid(args.uid)
        .gid(args.gid)
        .mount_proc(args.mount_proc);

    if let Some(time_limit) = args.time_limit {
        config.time_limit(time_limit);
    }

    if let Some(memory_limit) = args.memory_limit {
        config.memory_limit(memory_limit * 1_000_000);
    }

    if let Some(wall_limit) = args.wall_limit {
        config.wall_time_limit(wall_limit);
    }

    if let Some(stdin) = args.stdin {
        config.stdin(stdin);
    }

    if let Some(stdout) = args.stdout {
        config.stdout(stdout);
    }

    if let Some(stderr) = args.stderr {
        config.stderr(stderr);
    }

    if let Some(working_directory) = args.working_directory {
        config.working_directory(working_directory);
    }

    if let Some(core) = args.cpu_core {
        config.run_on_core(core);
    }

    for arg in args.args {
        config.arg(arg);
    }

    for el in args.env {
        let parts: Vec<&str> = el.splitn(2, '=').collect();
        match parts.len() {
            1 => {
                let name = parts[0];
                let value = std::env::var(name).with_context(|| {
                    format!("Variable {} not present in the environment", parts[0])
                })?;
                config.env(name, value);
            }
            2 => {
                config.env(parts[0], parts[1]);
            }
            _ => bail!("Invalid env argument: {}", el),
        }
    }

    for path in args.mount {
        let parts: Vec<&str> = path.split(',').collect();
        let (local, sandbox, writable) = match parts[..] {
            [local] => (local, local, false),
            [local, "rw"] => (local, local, true),
            [local, sandbox] => (local, sandbox, false),
            [local, sandbox, "rw"] => (local, sandbox, true),
            [local, sandbox, "ro"] => (local, sandbox, false),
            _ => bail!("Invalid mount point: {}", path),
        };
        debug!(
            "Mount {} into {} ({})",
            local,
            sandbox,
            if writable { "rw" } else { "ro" }
        );
        config.mount(PathBuf::from(local), PathBuf::from(sandbox), writable);
    }

    config.syscall_filter(SyscallFilter::build(
        args.allow_multiprocess,
        args.allow_chmod,
    ));

    trace!("Sandbox config {:#?}", config);

    let sandbox =
        SandboxImplementation::run(config.build()).context("Error running the sandbox")?;
    let result = sandbox.wait().context("Error waiting for sandbox result")?;

    if args.json {
        eprintln!("{}", serde_json::to_string(&result).unwrap());
    } else {
        eprintln!("{:#?}", result);
    }
    Ok(())
}
