---
name: "Package Hijacking"
packageManager: "npm"
slug: "npm-package-hijacking"
category: "Supply Chain"
severity: "critical"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "Package hijacking occurs when an attacker gains control of a legitimate maintainer's npm publishing authority and publishes trojanized versions of popular packages. Because npm packages often have deep transitive dependency trees, compromising one widely used package can affect many downstream projects. In March 2026, malicious Axios versions 1.14.1 and 0.30.4 reached an ecosystem with more than 70 million weekly downloads according to Microsoft. Microsoft attributed the supporting infrastructure and compromise to Sapphire Sleet."
descriptionCitations: [1, 2, 3, 4, 5, 6, 7, 8]
prerequisites:
  - "Compromised npm maintainer credentials via phishing, credential stuffing, or token leakage"
  - "Target package must have a significant number of downstream dependents to maximize blast radius"
prerequisitesCitations: [1, 2, 3, 4, 5, 6, 7, 8]
attackScenarios:
  - title: "Account Takeover and Trojanized Publish"
    description: "An attacker compromises a maintainer's npm account and publishes a new patch version containing a malicious dependency. A fresh resolution or dependency update can select that patch when a semver range permits it; an existing lockfile can keep the older version. In the March 2026 Axios attack, the attacker changed a primary maintainer account's registered email and published two backdoored versions within a 39-minute window. npm 12 now blocks unapproved dependency install scripts by default, but this does not prevent malicious runtime code in a selected package."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - label: "Attacker logs in with compromised credentials and publishes"
        code: |
          npm login --auth-type=legacy
          # Using compromised credentials
          npm publish
        language: "bash"
      - label: "Trojanized package.json injecting a malicious dependency (as in the Axios attack)"
        code: |
          {
            "name": "axios",
            "version": "1.14.1",
            "dependencies": {
              "plain-crypto-js": "4.2.1"
            }
          }
        language: "json"
      - label: "The malicious dependency (plain-crypto-js) delivers a cross-platform RAT via its own postinstall"
        code: |
          {
            "name": "plain-crypto-js",
            "version": "4.2.1",
            "scripts": {
              "postinstall": "node scripts/postinstall.js"
            }
          }
          // The postinstall script downloads and executes a platform-specific
          // remote access trojan (RAT) for macOS, Windows, or Linux
        language: "javascript"
  - title: "Transitive Dependency Amplification"
    description: "A package deep in the dependency tree is compromised. Because it is a transitive dependency of many popular frameworks, the malicious code reaches thousands of projects that never directly depend on the hijacked package and may not even be aware it exists in their dependency tree."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - label: "Viewing dependencies and dependents to assess blast radius"
        code: |
          # Check a package's dependencies
          PACKAGE=axios
          npm view "$PACKAGE" --json | jq '.dependencies'
          # To find who depends on a package, check:
          # https://www.npmjs.com/browse/depended/axios
          # Or use npm.anvaka.com to visualize the dependency graph
        language: "bash"
detection:
  - title: "Monitor for Unexpected Version Bumps"
    description: "Set up alerts for new versions of your critical dependencies. Compare published versions against the project's GitHub releases or changelog to detect unauthorized publishes."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - code: "npm view axios versions --json | jq '.[-5:]'"
        language: "bash"
  - title: "Lockfile Integrity Verification"
    description: "Use npm ci instead of npm install to enforce the exact versions and integrity hashes recorded in package-lock.json. Any tampering with the published tarball will cause a checksum mismatch and fail the install."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - code: "npm ci"
        language: "bash"
  - title: "Use Registry Advisories as a Separate Signal"
    description: "npm audit submits dependency information to the configured registry's audit endpoint and reports known advisories. It can identify a compromise after an advisory exists, but it is not a general detector for new malicious package behavior."
    citations: [1, 2, 3, 4, 5, 6, 7, 8]
    commands:
      - code: "npm audit --audit-level=moderate"
        language: "bash"
mitigation:
  - "Enable two-factor authentication (2FA) on all npm maintainer accounts, especially for packages with large install bases"
  - "Use npm ci in CI/CD pipelines to enforce lockfile integrity and detect unexpected changes"
  - "Pin exact dependency versions and review all version bumps before merging"
  - "Monitor npm advisory feeds and subscribe to security notifications for critical dependencies"
  - "Use npm provenance attestations to verify that published packages were built from the expected source repository"
  - "On npm 12, keep dependency install scripts default-denied and approve only reviewed, version-pinned scripts"
mitigationCitations: [1, 2, 3, 4, 5, 6, 7, 8]
references:
  - title: "Supply Chain Attack on Axios npm Package - Socket.dev"
    url: "https://socket.dev/blog/axios-npm-package-compromised"
  - title: "Mitigating the Axios npm Supply Chain Compromise - Microsoft Security Blog"
    url: "https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/"
  - title: "Inside the Axios Supply Chain Compromise - Elastic Security Labs"
    url: "https://www.elastic.co/security-labs/axios-one-rat-to-rule-them-all"
  - title: "npm Two-Factor Authentication Documentation"
    url: "https://docs.npmjs.com/configuring-two-factor-authentication"
  - title: "npm Provenance Attestations"
    url: "https://docs.npmjs.com/generating-provenance-statements"
  - title: "ua-parser-js Hijacking Incident (2021)"
    url: "https://github.com/faisalman/ua-parser-js/issues/536"
  - title: "npm audit Documentation"
    url: "https://docs.npmjs.com/cli/v12/commands/npm-audit/"
  - title: "GitHub - npm 12 Install-Time Security Defaults"
    url: "https://github.blog/changelog/2026-07-08-npm-install-time-security-and-gat-bypass2fa-deprecation/"
created: 2026-04-02
updated: 2026-10-14
---
