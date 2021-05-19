// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use crate::configuration::{DirectoryMount, SandboxConfiguration};
use crate::Result;

use nix::mount::{mount, MsFlags};
use nix::sys::stat::{mknod, Mode, SFlag};
use std::fs;
use std::path::Path;

/// Create the sandbox filesystem
pub fn create(config: &SandboxConfiguration, sandbox_path: &Path) -> Result<()> {
    // Create the sandbox dir and mount a tmpfs in it
    mount(
        Some("tmpfs"),
        sandbox_path,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=256M,mode=0755"),
    )?;

    // Create /dev
    let dev = sandbox_path.join("dev");
    fs::create_dir_all(&dev)?;

    for device in &["null", "zero", "random", "urandom"] {
        mount_dev(&dev.join(device), device)?;
    }

    // Mount /tmp and /dev/shm
    if config.mount_tmpfs {
        for path in &["tmp", "dev/shm"] {
            let path = sandbox_path.join(path);
            fs::create_dir_all(&path)?;
            mount(
                Some("tmpfs"),
                &path,
                Some("tmpfs"),
                MsFlags::empty(),
                Some("size=256M"),
            )?;
        }
    }

    if config.mount_proc {
        fs::create_dir_all(sandbox_path.join("proc"))?;
        mount(Some("proc"), &sandbox_path.join("proc"), Some("proc"), MsFlags::empty(), Some("none"))?;
    }

    // bind mount the readable directories into the sandbox
    for dir in &config.mount_paths {
        mount_dir(dir, sandbox_path)?;
    }

    // Remount tmpfs read only
    mount(
        None as Option<&str>,
        sandbox_path,
        None as Option<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None as Option<&str>,
    )?;
    Ok(())
}

/// Create a device
fn mount_dev(path: &Path, dev: &str) -> nix::Result<()> {
    mknod(
        path,
        SFlag::empty(),
        Mode::S_IRUSR
            | Mode::S_IWUSR
            | Mode::S_IRGRP
            | Mode::S_IWGRP
            | Mode::S_IROTH
            | Mode::S_IWOTH,
        0,
    )?;
    mount(
        Some(&Path::new("/dev").join(dev)),
        path,
        None as Option<&str>,
        MsFlags::MS_BIND,
        None as Option<&str>,
    )
}

/// Mount a directory inside the sandbox
fn mount_dir(dir: &DirectoryMount, sandbox_dir: &Path) -> Result<()> {
    trace!("Mount {:?}", dir);
    assert_ne!(dir.target, Path::new("/"));

    // Join destination with the sandbox directory
    let target = sandbox_dir.join(dir.target.strip_prefix("/")?);

    fs::create_dir_all(&target)?;

    mount(
        Some(&dir.source),
        &target,
        None as Option<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None as Option<&str>,
    )?;

    if !dir.writable {
        mount(
            None as Option<&str>,
            &target,
            None as Option<&str>,
            MsFlags::MS_REMOUNT
                | MsFlags::MS_RDONLY
                | MsFlags::MS_BIND
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV,
            None as Option<&str>,
        )?;
    }
    Ok(())
}
