// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use crate::configuration::{DirectoryMount, SandboxConfiguration};
use libc::*;
use std::ffi::CString;
use std::fs;
use std::path::Path;

/// Create the sandbox filesystem
pub fn create(config: &SandboxConfiguration, sandbox_path: &Path) {
    // Create the sandbox dir and mount a tmpfs in it
    mount("tmpfs", &sandbox_path, "tmpfs", 0, "size=256M");

    // Create /dev
    let dev = sandbox_path.join("dev");
    fs::create_dir_all(&dev).unwrap();

    make_dev(&dev.join("null"), 1, 3);
    make_dev(&dev.join("zero"), 1, 5);
    make_dev(&dev.join("random"), 1, 8);
    make_dev(&dev.join("urandom"), 1, 9);

    // Mount /tmp and /dev/shm
    if config.mount_tmpfs {
        mount("tmpfs", &sandbox_path.join("tmp"), "tmpfs", 0, "size=256M");
        mount(
            "tmpfs",
            &sandbox_path.join("dev/shm"),
            "tmpfs",
            0,
            "size=256M",
        );
    }

    // bind mount the readable directories into the sandbox
    for dir in &config.mount_paths {
        mount_dir(dir, sandbox_path);
    }

    // Remount tmpfs read only
    mount("tmpfs", &sandbox_path, "tmpfs", MS_REMOUNT | MS_RDONLY, "");
}

/// Create a device
fn make_dev(path: &Path, major: u32, minor: u32) {
    trace!(
        "Make device {:?} with major = {}, minor = {}",
        path,
        major,
        minor
    );
    let dev = CString::new(path.to_str().unwrap()).unwrap();
    check_syscall!(mknod(
        dev.as_ptr(),
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
        makedev(major, minor)
    ));
}

/// Mount a directory inside the sandbox
fn mount_dir(dir: &DirectoryMount, sandbox_dir: &Path) {
    trace!("Mount {:?}", dir);
    assert_ne!(dir.target, Path::new("/"));

    // Join destination with the sandbox directory
    let target = sandbox_dir.join(dir.target.strip_prefix("/").unwrap());

    mount(
        dir.source.to_str().unwrap(),
        &target,
        "",
        MS_BIND | MS_REC,
        "",
    );

    if !dir.writable {
        mount("", &target, "", MS_REMOUNT | MS_RDONLY | MS_BIND, "");
    }
}

/// Wrapper around mount system call
fn mount(source: &str, target: &Path, fstype: &str, options: u64, data: &str) {
    fs::create_dir_all(target).unwrap();

    trace!(
        "mount({}, {:?}, {}, {}, {})",
        source,
        target,
        fstype,
        options,
        data
    );
    let source = CString::new(source).unwrap();
    let target = CString::new(target.to_str().unwrap()).unwrap();
    let fstype = CString::new(fstype).unwrap();
    let data = CString::new(data).unwrap();

    check_syscall!(libc::mount(
        source.as_ptr(),
        target.as_ptr(),
        fstype.as_ptr(),
        options,
        data.as_ptr() as *const c_void,
    ));
}
