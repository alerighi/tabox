// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use std::fs;
use std::path::Path;

use anyhow::Context;
use nix::mount::{mount, MsFlags};
use nix::sys::stat::{mknod, Mode, SFlag};

use crate::configuration::{DirectoryMount, SandboxConfiguration};
use crate::Result;

/// Create the sandbox filesystem
pub fn create(config: &SandboxConfiguration, sandbox_path: &Path) -> Result<()> {
    // Create the sandbox dir and mount a tmpfs in it
    mount(
        Some("tmpfs"),
        sandbox_path,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=256M,mode=0755"),
    )
    .context("Failed to mount tmpfs for the sandbox")?;

    // Create /dev
    let dev = sandbox_path.join("dev");
    fs::create_dir_all(&dev).context("Failed to create /dev for the sandbox")?;

    for device in &["null", "zero", "random", "urandom"] {
        mount_dev(&dev.join(device), device)
            .with_context(|| format!("Failed to mount /dev/{} in the sandbox", device))?;
    }

    // Mount /tmp and /dev/shm
    if config.mount_tmpfs {
        for path in &["tmp", "dev/shm"] {
            let target_path = sandbox_path.join(path);
            fs::create_dir_all(&target_path)
                .with_context(|| format!("Failed to create /{} in the sandbox", path))?;
            mount(
                Some("tmpfs"),
                &target_path,
                Some("tmpfs"),
                MsFlags::empty(),
                Some("size=256M"),
            )
            .with_context(|| {
                format!(
                    "Failed to mount tmpfs for /{} at {}",
                    path,
                    target_path.display()
                )
            })?;
        }
    }

    if config.mount_proc {
        let target = sandbox_path.join("proc");
        fs::create_dir_all(&target).context("Failed to create /proc in the sandbox")?;
        mount(
            Some("proc"),
            &target,
            Some("proc"),
            MsFlags::empty(),
            None::<&str>,
        )
        .with_context(|| format!("Failed to mount proc at {}", target.display()))?;
    }

    // bind mount the readable directories into the sandbox
    for dir in &config.mount_paths {
        mount_dir(dir, sandbox_path).with_context(|| {
            format!(
                "Failed to mount {} -> {}",
                dir.source.display(),
                dir.target.display()
            )
        })?;
    }

    // Remount tmpfs read only
    mount(
        None as Option<&str>,
        sandbox_path,
        None as Option<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None as Option<&str>,
    )
    .context("Failed to remount sandbox directory as readonly")?;
    Ok(())
}

/// Create a device
fn mount_dev(path: &Path, dev: &str) -> Result<()> {
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
    )
    .with_context(|| format!("Failed to mknod {}", path.display()))?;
    mount(
        Some(&Path::new("/dev").join(dev)),
        path,
        None as Option<&str>,
        MsFlags::MS_BIND,
        None as Option<&str>,
    )
    .with_context(|| format!("Failed to bind-mount /dev/{}", dev))
}

/// Mount a directory inside the sandbox
fn mount_dir(dir: &DirectoryMount, sandbox_dir: &Path) -> Result<()> {
    trace!("Mount {:?}", dir);
    assert_ne!(dir.target, Path::new("/"));

    // Join destination with the sandbox directory
    let target = sandbox_dir.join(dir.target.strip_prefix("/")?);

    fs::create_dir_all(&target)
        .with_context(|| format!("Failed to create mount target at {}", target.display()))?;

    mount(
        Some(&dir.source),
        &target,
        None as Option<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None as Option<&str>,
    )
    .with_context(|| {
        format!(
            "Failed to bind-mount {} -> {}",
            dir.source.display(),
            target.display()
        )
    })?;

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
        )
        .with_context(|| format!("Failed to readonly remount at {}", target.display()))?;
    }
    Ok(())
}
