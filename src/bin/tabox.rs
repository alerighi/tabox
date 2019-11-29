// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

extern crate env_logger;
extern crate structopt;
#[macro_use]
extern crate log;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use structopt::StructOpt;
use tabox::{
    BindMount, DirectoryMount, Sandbox, SandboxConfigurationBuilder, SandboxImplementation,
    SyscallFilter, SyscallFilterAction,
};

/// Command line arguments of the program
#[derive(Debug, Clone, Serialize, Deserialize, StructOpt)]
#[structopt(name = "tabox", about = "Execute code in a secure sandbox")]
struct Args {
    /// Time limit for the execution
    #[structopt(long, short)]
    time_limit: Option<u64>,

    /// Memory limit fot the execution
    #[structopt(long, short)]
    memory_limit: Option<u64>,

    /// Absolute path of the executable
    executable: PathBuf,

    /// Arguments to pass to the executable
    args: Vec<String>,

    /// Environment to pass to the executable
    #[structopt(long)]
    env: Vec<String>,

    /// Allowed paths inside the sandbox
    #[structopt(long = "allow", short = "a")]
    allowed_paths: Vec<PathBuf>,

    /// Working directory for the process. Of course must be a directory mounted
    #[structopt(long)]
    working_directory: Option<PathBuf>,

    /// Allow only these system calls in the sandbox
    #[structopt(long)]
    syscall_filter: Option<Vec<String>>,

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

    /// Mount a tmpfs in /tmp
    #[structopt(long)]
    mount_tmp: bool,
}

fn main() {
    env_logger::init();

    let args = Args::from_args();

    if !SandboxImplementation::is_secure() && !args.allow_insecure {
        eprintln!("Your platform doesn't support a secure sandbox!");
        eprintln!("Run with --allow-insecure if you really want to execute it anyway");
        return;
    }

    let mut config = SandboxConfigurationBuilder::default();

    config.executable(args.executable);

    if let Some(time_limit) = args.time_limit {
        config.time_limit(time_limit);
    }

    if let Some(memory_limit) = args.memory_limit {
        config.memory_limit(memory_limit);
    }

    if let Some(stdin) = args.stdin {
        config.stdin(stdin);
    }

    if let Some(stdout) = args.stdout {
        config.stdin(stdout);
    }

    if let Some(stderr) = args.stderr {
        config.stdin(stderr);
    }

    if let Some(working_directory) = args.working_directory {
        config.working_directory(working_directory);
    }

    for arg in args.args {
        config.arg(arg);
    }

    for el in args.env {
        let el: String = el;
        let parts: Vec<&str> = el.split("=").collect();
        match parts.len() {
            1 => {
                config.env(parts[0], std::env::var(parts[0])
                    .expect(&format!("Variable {} not present in the environment", parts[0])));
            },
            2 => {
                config.env(parts[0], parts[1]);
            },
            _ => panic!("Invalid env argument"),
        }
    }

    for path in args.allowed_paths {
        config.mount(DirectoryMount::Bind(BindMount {
            source: path.clone(),
            target: path.clone(),
            writable: false,
        }));
    }

    if args.mount_tmp {
        config.mount(DirectoryMount::Tmpfs(PathBuf::from("/tmp")));
    }

    if let Some(syscall_filter) = args.syscall_filter {
        config.syscall_filter(SyscallFilter {
            default_action: SyscallFilterAction::Kill,
            rules: syscall_filter
                .iter()
                .map(|p| (p.clone(), SyscallFilterAction::Allow))
                .collect(),
        });
    }

    trace!("Sandbox config {:#?}", config);

    let sandbox = SandboxImplementation::run(config.build()).expect("Error creating sandbox");
    let result = sandbox.wait().expect("Error waiting for sandbox result");

    if args.json {
        println!("{}", serde_json::to_string(&result).unwrap());
    } else {
        println!("{:#?}", result);
    }
}
