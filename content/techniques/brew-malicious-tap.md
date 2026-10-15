---
name: "Trusted Third-Party Tap Supply Chain"
packageManager: "brew"
slug: "brew-malicious-tap"
category: "Supply Chain"
severity: "high"
platform:
  - "macOS"
  - "Linux"
description: "`brew tap <user>/<repo>` clones a third-party repository that can provide formulae, casks, and external commands, but tapping alone does not grant whole-tap trust. Since Homebrew 6.0.0, non-official taps require explicit trust by default. Installing a fully qualified item trusts only that item; `brew trust` can instead trust a specific item or the entire tap. A malicious or compromised item can run Ruby with the user's privileges when Homebrew loads it, so broad or stale trust entries create the supply-chain risk."
descriptionCitations: [1, 2, 3, 4, 5]
prerequisites:
  - "Victim installs an attacker-controlled fully qualified item, explicitly trusts that item, or trusts the whole tap"
  - "Homebrew later loads the trusted formula, cask, or command; `brew update` alone can fetch changes but does not by itself grant trust"
  - "For typosquat variants: a name close enough to a legitimate tap to trick users (e.g. `hashicorp/tap` vs `hashi-corp/tap`)"
prerequisitesCitations: [1, 2, 3, 4, 5]
attackScenarios:
  - title: "Typosquatted Tap Mimicking a Popular Vendor"
    description: "An attacker registers a GitHub repository named `homebrew-<product>` under an organization that resembles a real vendor and seeds it with convincingly named formulae. A user who installs the fully qualified formula makes an explicit trust decision for that item. The trust boundary therefore depends on social engineering the user into choosing the attacker's namespace, rather than on `brew tap` silently authorizing the repository."
    citations: [1, 2, 3, 4, 5]
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
            # Illustrative digest; a real formula must match its source archive.
            sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

            # Formula-body Ruby runs when Homebrew loads this trusted formula.
            File.write("/tmp/terraform-formula-loaded", Time.now.to_s)

            def install
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
          brew install hashi-corp/tap/terraform
          # The fully qualified command trusts only this formula, then loads it.
        language: "bash"
  - title: "Compromised Tap Pushing a Silent Update"
    description: "An attacker who compromises an existing tap can modify a formula that users already trust. `brew update` can fetch the changed repository, and a later operation that loads or upgrades the trusted formula can evaluate the new Ruby. Trust is attached to the item or tap rather than to a reviewed commit, so users must separately review updates when that distinction matters."
    citations: [1, 2, 3, 4, 5]
    commands:
      - label: "Attacker pushes a minimal malicious diff"
        code: |
          # Single-commit diff to an existing, trusted formula in the tap
          diff --git a/Formula/widget.rb b/Formula/widget.rb
          --- a/Formula/widget.rb
          +++ b/Formula/widget.rb
          @@ class Widget < Formula
          +  File.write("/tmp/widget-formula-loaded", Time.now.to_s)
          +
             def install
               bin.install "widget"
             end
        language: "bash"
      - label: "Victim runs an operation that performs Homebrew auto-update"
        code: |
          brew update
          # Fetches the changed tap; the update itself is not the execution step.
          brew upgrade widget
          # Loading the already-trusted formula evaluates the changed Ruby.
        language: "bash"
  - title: "Overriding a Core Formula From an Attacker Tap"
    description: "If a user installs a formula by its fully qualified tap path (`attacker/tap/jq`), Homebrew selects that item even if `homebrew/core` also has `jq`; the command also trusts that individual third-party formula. The unqualified command `brew install jq` continues to select the core formula, so the attacker must persuade the user to choose the hostile namespace."
    citations: [1, 2, 3, 4, 5]
    commands:
      - label: "Attacker tap overrides a core formula name"
        code: |
          # Formula/jq.rb in attacker/homebrew-utils
          class Jq < Formula
            desc "Command-line JSON processor (faster build)"
            url "https://example.com/jq-1.7.tar.gz"
            sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

            def install
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
    description: "Every tap is a git clone under `$(brew --repository)/Library/Taps`. List taps, trust entries, and remotes, then confirm each resolves to the intended organization. Unexpected taps or broader-than-needed trust entries warrant review."
    citations: [1, 2, 3, 4, 5]
    commands:
      - code: |
          brew tap
          brew trust
          brew untrust
          for t in $(brew tap); do
            echo "=== $t ==="
            git -C "$(brew --repository)/Library/Taps/${t/\//\/homebrew-}" remote -v
          done
        language: "bash"
  - title: "Review tap git history before upgrading"
    description: "Diff a trusted tap's recent commits before running an upgrade when you need commit-level review. Homebrew's item and tap trust entries do not attest to a specific repository revision."
    citations: [1, 2, 3, 4, 5]
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
    citations: [1, 2, 3, 4, 5]
    commands:
      - code: |
          # Example: list taps present across a fleet via MDM / osquery
          osqueryi --json "SELECT path FROM file WHERE path LIKE '/opt/homebrew/Library/Taps/%/homebrew-%' AND type = 'directory';"
        language: "bash"
mitigation:
  - "Prefer item-level trust (`brew trust --formula`, `--cask`, or `--command`) and grant whole-tap trust only when every current and future item is acceptable"
  - "Before installing, verify the organization and fully qualified item name against the vendor's official documentation"
  - "Set `HOMEBREW_NO_AUTO_UPDATE=1` in CI and dev shells so tap updates do not land without explicit review"
  - "Pin critical taps to a reviewed commit with `git -C $(brew --repository)/Library/Taps/<tap> checkout <sha>`"
  - "Periodically audit `brew tap` output and remove taps the team no longer uses (`brew untap`)"
  - "Restrict cloning scope at the network layer for managed fleets to approved GitHub organizations"
  - "Prefer the fully-qualified form (`homebrew/core/jq`) when scripting installs, so a tap cannot shadow a core formula"
mitigationCitations: [1, 2, 3, 4, 5]
references:
  - title: "Homebrew Taps Documentation"
    url: "https://docs.brew.sh/Taps"
  - title: "brew tap manpage"
    url: "https://docs.brew.sh/Manpage#tap-options-user-repo-url"
  - title: "Homebrew how-to: creating and maintaining a tap"
    url: "https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap"
  - title: "Homebrew Tap Trust"
    url: "https://docs.brew.sh/Tap-Trust"
  - title: "Homebrew Security and Supply Chain"
    url: "https://docs.brew.sh/Homebrew-Security-and-Supply-Chain"
created: 2026-04-21
updated: 2026-10-14
---
