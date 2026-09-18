// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Build script for spl-bridge recording provenance and worktree state.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let (git_dir, git_available) = resolve_git_dir(&manifest_dir);

    if !git_available {
        println!("cargo:rustc-env=SPL_BRIDGE_BUILD_ID=unavailable");
        println!("cargo:rerun-if-changed=.git");
        return;
    }

    // Track .git/HEAD and .git/index
    let head_path = git_dir.join("HEAD");
    if head_path.is_file() {
        println!("cargo:rerun-if-changed={}", head_path.display());
        if let Ok(head_content) = fs::read_to_string(&head_path) {
            let head_content = head_content.trim();
            if let Some(ref_path) = head_content.strip_prefix("ref:") {
                let resolved_ref = git_dir.join(ref_path.trim());
                if resolved_ref.is_file() {
                    println!("cargo:rerun-if-changed={}", resolved_ref.display());
                }
            }
        }
    }

    let index_path = git_dir.join("index");
    if index_path.is_file() {
        println!("cargo:rerun-if-changed={}", index_path.display());
    }

    // Track every tracked file from git ls-files for unstaged worktree edits
    if let Ok(output) = Command::new("git")
        .current_dir(&manifest_dir)
        .args(["ls-files"])
        .output()
        && output.status.success()
        && let Ok(files) = std::str::from_utf8(&output.stdout)
    {
        for file in files.lines() {
            let file = file.trim();
            if !file.is_empty() {
                let path = manifest_dir.join(file);
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    let build_id = determine_build_id(&manifest_dir);
    println!("cargo:rustc-env=SPL_BRIDGE_BUILD_ID={build_id}");
}

fn resolve_git_dir(start_dir: &Path) -> (PathBuf, bool) {
    let mut current = Some(start_dir);
    while let Some(dir) = current {
        let dot_git = dir.join(".git");
        if dot_git.is_dir() {
            return (dot_git, true);
        } else if dot_git.is_file()
            && let Ok(content) = fs::read_to_string(&dot_git)
            && let Some(gitdir) = content.trim().strip_prefix("gitdir:")
        {
            let gitdir_path = gitdir.trim();
            let resolved = if Path::new(gitdir_path).is_absolute() {
                PathBuf::from(gitdir_path)
            } else {
                dir.join(gitdir_path)
            };
            if resolved.exists() {
                return (resolved, true);
            }
        }
        current = dir.parent();
    }
    (PathBuf::from(".git"), false)
}

fn determine_build_id(start_dir: &Path) -> String {
    let head_rev = Command::new("git")
        .current_dir(start_dir)
        .args(["rev-parse", "HEAD"])
        .output();

    let Ok(head_output) = head_rev else {
        return String::from("unavailable");
    };

    if !head_output.status.success() {
        return String::from("unavailable");
    }

    let Ok(head_str) = std::str::from_utf8(&head_output.stdout) else {
        return String::from("unavailable");
    };
    let commit_hex = head_str.trim();
    if commit_hex.is_empty() {
        return String::from("unavailable");
    }

    let diff_index = Command::new("git")
        .current_dir(start_dir)
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .status();

    let status_output = Command::new("git")
        .current_dir(start_dir)
        .args(["status", "--porcelain=v1", "-uno"])
        .output();

    let is_clean = match (diff_index, status_output) {
        (Ok(diff_status), Ok(status_out)) => diff_status.success() && status_out.stdout.is_empty(),
        _ => false,
    };

    if is_clean {
        commit_hex.to_owned()
    } else {
        format!("{commit_hex}-dirty")
    }
}
