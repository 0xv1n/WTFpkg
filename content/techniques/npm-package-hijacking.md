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
description: "Package hijacking occurs when an attacker gains control of a legitimate maintainer's npm account and publishes trojanized versions of popular packages. Because npm packages often have deep transitive dependency trees, compromising a single widely-used package can affect thousands of downstream projects. The March 2026 Axios attack demonstrated how a hijacked maintainer account was used to publish backdoored versions (1.14.1 and 0.30.4), threatening the approximately 100 million projects that download Axios weekly. The attack was attributed to the North Korean state actor Sapphire Sleet (also tracked as UNC1069) and the malicious versions were removed by npm within approximately 2-3 hours."
prerequisites:
  - "Compromised npm maintainer credentials via phishing, credential stuffing, or token leakage"
  - "Target package must have a significant number of downstream dependents to maximize blast radius"
attackScenarios:
  - title: "Account Takeover and Trojanized Publish"
    description: "An attacker compromises a maintainer's npm account and publishes a new patch version of a popular package containing a malicious dependency. Since most consumers use semver ranges like ^x.y.z, the malicious patch is automatically installed on the next npm install. In the March 2026 Axios attack, the attacker compromised the account of a primary maintainer (jasonsaayman), changed its registered email, and published two backdoored versions within a 39-minute window."
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
    commands:
      - label: "Viewing dependencies and dependents to assess blast radius"
        code: |
          # Check a package's dependencies
          npm view <package-name> --json | jq '.dependencies'
          # To find who depends on a package, check:
          # https://www.npmjs.com/browse/depended/<package-name>
          # Or use npm.anvaka.com to visualize the dependency graph
        language: "bash"
detection:
  - title: "Monitor for Unexpected Version Bumps"
    description: "Set up alerts for new versions of your critical dependencies. Compare published versions against the project's GitHub releases or changelog to detect unauthorized publishes."
    commands:
      - code: "npm view axios versions --json | jq '.[-5:]'"
        language: "bash"
  - title: "Lockfile Integrity Verification"
    description: "Use npm ci instead of npm install to enforce the exact versions and integrity hashes recorded in package-lock.json. Any tampering with the published tarball will cause a checksum mismatch and fail the install."
    commands:
      - code: "npm ci"
        language: "bash"
  - title: "Run npm audit Regularly"
    description: "npm audit checks your dependency tree against the GitHub Advisory Database for known vulnerabilities and compromised packages."
    commands:
      - code: "npm audit --audit-level=moderate"
        language: "bash"
mitigation:
  - "Enable two-factor authentication (2FA) on all npm maintainer accounts, especially for packages with large install bases"
  - "Use npm ci in CI/CD pipelines to enforce lockfile integrity and detect unexpected changes"
  - "Pin exact dependency versions and review all version bumps before merging"
  - "Monitor npm advisory feeds and subscribe to security notifications for critical dependencies"
  - "Use npm provenance attestations to verify that published packages were built from the expected source repository"
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
created: 2026-04-02
updated: 2026-04-02
---
