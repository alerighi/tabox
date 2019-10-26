use std::collections::HashMap;
use std::num::NonZeroUsize;
use crate::isolate::NonZeroQuantity::Value;

#[derive(Copy, Clone, Debug)]
pub enum NonZeroQuantity {
    Value(NonZeroUsize),
    Unlimited
}

impl NonZeroQuantity {
    fn to_representation(&self) -> usize {
        match self {
            NonZeroQuantity::Value(x) => x.get(),
            NonZeroQuantity::Unlimited => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SandboxDirectory<'a> {
    src: &'a str,
    dst: Option<&'a str>,
    options: Vec<&'a str> // TODO: add enum
}

#[derive(Builder, Debug)]
pub struct IsolateSandbox<'a> {
    /// -b When multiple sandboxes are used in parallel, each must get a unique ID
    box_id: Option<u8>,
    /// --cg Enable use of control groups
    use_cgroups: bool,
    /// -c Change directory to <dir> before executing the program
    chdir: Option<&'a str>,
    /// -d Make a directory <dir> visible inside the sandbox
    visible_dirs: Vec<SandboxDirectory<'a>>,
    /// -e Inherit full environment of the parent process
    preserve_env: bool,
    /// -E Inherit the environment variable <var> from the parent process
    inherit_env: Vec<&'a str>,
    /// -E Set the environment variable <var> to <val>; unset it if <var> is empty
    set_env: HashMap<&'a str, &'a str>,
    /// -f Max size (in KB) of files that can be created
    max_file_size: NonZeroQuantity,
    /// -k Limit stack size to <size> (rounded to nearest KB)
    stack_space: NonZeroQuantity,
    /// -m Limit address space to <size> (rounded to nearest KB)
    address_space: NonZeroQuantity,
    /// -i Redirect stdin from <file>
    stdin_file: Option<&'a str>,
    /// -o Redirect stdout to <file>
    stdout_file: Option<&'a str>,
    /// -r Redirect stderr to <file>
    stderr_file: Option<&'a str>,
    /// -t Set run time limit (milliseconds)
    timeout: NonZeroQuantity,
    /// -v Be verbose (higher values mean more verbose)
    verbosity: u8,
    /// -w Set wall clock time limit
    wallclock_timeout_ms: NonZeroQuantity,
    /// -x Set extra timeout, before which a timing-out program is not yet killed,
    ///	so that its real execution time is reported
    extra_timeout_ms: NonZeroQuantity,
    /// -p Enable multiple processes (at most <max> of them); needs --cg
    max_processes: usize
}

impl Default for IsolateSandbox<'_> {
    fn default() -> Self {
        IsolateSandbox {
            box_id: None,
            use_cgroups: false,
            chdir: None,
            visible_dirs: vec![],
            preserve_env: false,
            inherit_env: vec![],
            set_env: Default::default(),
            max_file_size: NonZeroQuantity::Unlimited,
            stack_space: NonZeroQuantity::Unlimited,
            address_space: NonZeroQuantity::Unlimited,
            stdin_file: None,
            stdout_file: None,
            stderr_file: None,
            timeout: NonZeroQuantity::Unlimited,
            verbosity: 0,
            wallclock_timeout_ms: NonZeroQuantity::Unlimited,
            extra_timeout_ms: NonZeroQuantity::Unlimited,
            max_processes: 1
        }
    }
}

fn build_box_options(config: IsolateSandbox) -> Vec<String> {

    let mut res: Vec<String> = Vec::new();

    if let Some(box_id) = config.box_id {
        res.push(format!("--box-id={}", box_id));
    }

    if config.use_cgroups {
        res.push(String::from("--cg"));
        res.push(String::from("--cg-timing"));
    }

    if let Some(chdir) = config.chdir {
        res.push(format!("--chdir={}", chdir));
    }

    for SandboxDirectory { src, dst, options } in config.visible_dirs {
        let mut cmd_param = format!("{}={}", src, dst.unwrap_or(src));
        if !options.is_empty() {
            cmd_param += (String::from(":") + options.join(",").as_str()).as_str();

        }
        res.push(format!("--dir={}", cmd_param));
    }

    if config.preserve_env {
        res.push(format!("--full-env"));
    }
    for var in config.inherit_env {
        res.push(format!("--env={}", var))
    }

    for (var, value) in config.set_env {
        res.push(format!("--env={}={}", var, value));
    }

    if let Value(bytes) = config.max_file_size {
        res.push(format!("-f {}", bytes));
    }
    // isolate wants file size as KiB.
    res.push(format!("--fsize={}", config.max_file_size.to_representation()));
    if let Some(stdin_file) = config.stdin_file {
        res.push(format!("--stdin={}", stdin_file));
    }
    // isolate wants stack size as KiB.
    if let Value(stack_space) = config.stack_space {
        res.push(format!("--stack={}", stack_space.get() / 1024));
    }
    // isolate wants memory size as KiB.
    if let Value(address_space) = config.address_space {
        if config.use_cgroups {
            res.push(format!("--cg-mem={}", address_space.get() / 1024));
        }
        else {
            res.push(format!("--mem={}", address_space.get() / 1024));
        }
    }
    if let Some(stdout_file) = config.stdout_file {
        res.push(format!("--stdout={}", /*config.inner_absolute_path*/ stdout_file));
    }
    if config.max_processes > 1 && config.use_cgroups {
        res.push(format!("--processes={}", config.max_processes));
    }
    else {
        res.push(format!("--processes"));
    }
    if let Some(stderr_file) = config.stderr_file {
        res.push(format!("--stderr={}", stderr_file));
    }
    if let Value(timeout) = config.timeout {
        res.push(format!("--time={}", timeout));
    }
    for i in 0..config.verbosity {
        res.push(format!("--verbose"));
    }

    if let Value(wallclock_timeout) = config.wallclock_timeout_ms {
        res.push(format!("--wall-time={}", wallclock_timeout));
    }
    if let Value(extra_timeout) = config.extra_timeout_ms {
        res.push(format!("--extra-time={}", extra_timeout));
    }
//    config.exe
//    res.push(format!("--meta={}.{}", config.info_basename, config.exec_num)));
    res.push(format!("--run"));
    res
}