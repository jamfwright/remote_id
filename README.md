# Remote Asset Identification Tool

A comprehensive reconnaissance tool for identifying ownership and accountability of internet-based assets. Built for security teams, IT administrators, and anyone who needs to verify whether an IP address, domain, or URL actually belongs to their organization.

## The Attribution Problem

**Third-party risk platforms get it wrong. A lot.**

Services like SecurityScoreCard, BitSight, Panorays, UpGuard, RiskRecon, and similar platforms attempt to assess an organization's security posture by scanning internet-facing assets they believe belong to that organization. The problem? **Asset attribution is fundamentally hard**, and misattribution is incredibly common.

These platforms may incorrectly attribute assets to your organization due to:

- **Stale WHOIS data** - Registration information that hasn't been updated after acquisitions, divestitures, or IP block transfers
- **Shared hosting environments** - Multiple organizations on the same IP ranges
- **CDN and cloud provider overlap** - Assets behind Cloudflare, Akamai, or AWS that serve multiple customers
- **Historical DNS records** - Domains that previously pointed to your infrastructure but have since changed hands
- **Subsidiary confusion** - Incorrectly associating parent companies with subsidiary infrastructure (or vice versa)
- **Similar naming** - Organizations with similar names getting assets mixed up

The result? Your organization's security score may be penalized for vulnerabilities on systems you don't own, have never owned, and have no ability to remediate. This creates real business impact during vendor assessments, contract negotiations, and cyber insurance evaluations.

### The Cloud Complication

Cloud-hosted infrastructure presents unique attribution challenges:

- **Ephemeral IP addresses** - Cloud IPs are constantly reassigned between customers
- **Serverless and containerized workloads** - Infrastructure that may exist for minutes or hours
- **Multi-tenant environments** - Shared responsibility models blur ownership lines
- **Rapid provisioning** - Assets spin up and down faster than scanning platforms can track
- **Region and availability zone changes** - Workloads migrate across cloud regions

An IP address that belonged to your organization yesterday may belong to someone else today. Third-party risk platforms scanning on weekly or monthly intervals cannot keep pace with this reality.

## What This Tool Does

`remote_id.py` performs deep reconnaissance on targets to help you determine true ownership and accountability:

| Method | Information Gathered |
|--------|---------------------|
| **DNS Resolution** | Forward/reverse lookups, FQDN identification |
| **DNS Records** | MX, NS, TXT (SPF/DKIM/DMARC), SOA, CAA records |
| **WHOIS/RDAP** | Network owner, country, CIDR block, registration details |
| **SSL Certificates** | Common Name, issuer, subject details across 27 ports |
| **HTTP Headers** | Server identification, technology stack, redirect chains |
| **Banner Grabbing** | Service identification on common ports (FTP, SSH, SMTP, etc.) |
| **Security.txt** | Contact information per RFC 9116 |
| **Shodan Integration** | Historical scan data, open ports, vulnerabilities, tags |

By correlating data from multiple sources, you can make informed decisions about whether an asset truly belongs to your organization.

## Installation

### Requirements

- Python 3.9+
- pip

### Install Dependencies

```bash
git clone https://github.com/jamfwright/remote_id.git
cd remote-asset-id
pip install -r requirements.txt
```

Or install packages individually:

```bash
pip install dnspython requests shodan ipwhois
```

### Optional: Shodan API Key

For enriched data including historical scans, known vulnerabilities, and service fingerprinting:

```bash
export SHODAN_API_KEY="your-api-key-here"
```

Get a free API key at [shodan.io](https://account.shodan.io/register)

## Usage

### Basic Scanning

```bash
# Single IP address
python3 remote_id.py 8.8.8.8

# Single domain
python3 remote_id.py example.com

# Multiple targets
python3 remote_id.py 8.8.8.8 1.1.1.1 cloudflare.com

# CIDR range (automatically expands)
python3 remote_id.py 192.168.1.0/28
```

### File Input

```bash
# Read targets from file (one per line)
python3 remote_id.py -f targets.txt

# Combine CLI targets with file input
python3 remote_id.py suspicious-ip.txt -f quarterly_review.txt
```

### Output Options

```bash
# JSON output to stdout
python3 remote_id.py example.com --json

# Save results to file
python3 remote_id.py example.com -o results.json

# Quiet mode (warnings only)
python3 remote_id.py example.com -q

# Verbose/debug mode
python3 remote_id.py example.com -v
```

### Performance Tuning

```bash
# Concurrent target scanning (default: 10 threads)
python3 remote_id.py -f large_list.txt -t 20

# Increase per-target port parallelism (default: 20)
python3 remote_id.py example.com --port-threads 30

# Sequential mode (disable parallelism)
python3 remote_id.py -f targets.txt --no-parallel
```

### Extended Scanning

```bash
# Thorough SSL scan (27 ports including Kubernetes, Docker, RDP, etc.)
python3 remote_id.py example.com --thorough

# Include Shodan enrichment data
python3 remote_id.py 8.8.8.8 --shodan

# Custom port lists
python3 remote_id.py example.com --ssl-ports 443,8443,9443 --banner-ports 22,80
```

### Real-World Examples

**Investigate a flagged IP from a risk platform:**
```bash
python3 remote_id.py 203.0.113.50 --shodan --thorough -o investigation.json
```

**Audit your organization's external footprint:**
```bash
python3 remote_id.py -f our_known_ips.txt -t 20 --shodan -o footprint_audit.json
```

**Quick ownership check:**
```bash
python3 remote_id.py suspicious-domain.com --json | jq '.[] | {target, whois_owner, whois_country}'
```

## Sample Output

```
======================================================================
ASSET IDENTIFICATION REPORT: example.com
======================================================================

[DNS/Network]
  Target:     example.com
  IP Address: 93.184.216.34
  FQDN:       example.com
  PTR:        example.com

[WHOIS Information]
  Owner:      EDGECAST
  Country:    US
  CIDR:       93.184.216.0/24

[DNS Records]
  Nameservers:
    - a.iana-servers.net
    - b.iana-servers.net
  TXT Records:
    - v=spf1 -all
    - DMARC: v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;

[SSL Certificates]
  Port 443: CN=www.example.org, Issuer=DigiCert Inc

[Notable HTTP Headers]
  Port 443 - Server: ECS (dcb/7F83)

[Shodan Intelligence]
  Organization: Edgecast Inc.
  ASN:          AS15133
  Location:     Los Angeles, US
  Open Ports:   80, 443
  Last Scan:    2024-01-15T08:23:45.000000

======================================================================
```

## SSL Ports Scanned

### Default (13 ports)
443, 8443, 636, 993, 995, 465, 563, 585, 614, 684, 695, 989, 990

### Extended with `--thorough` (27 ports)
Adds: 853 (DoT), 2083-2096 (cPanel), 2376 (Docker), 3389 (RDP), 4443, 5061 (SIP), 5671 (AMQP), 5986 (WinRM), 6443 (Kubernetes), 8883 (MQTT), 9443, 10443

## Use Cases

### Disputing Third-Party Risk Findings

When a risk platform flags an asset you don't recognize:

1. Run this tool against the flagged IP/domain
2. Document the WHOIS owner, SSL certificate details, and Shodan data
3. Use this evidence to dispute the finding with the platform
4. Request removal of incorrectly attributed assets from your profile

### Mergers & Acquisitions Due Diligence

Before acquiring a company:

1. Obtain their claimed IP ranges and domains
2. Verify actual ownership through WHOIS and certificate inspection
3. Identify shadow IT or unknown external assets
4. Assess exposure through Shodan vulnerability data

### Incident Response

When investigating a potential compromise:

1. Quickly determine if an IP is actually yours
2. Identify the hosting provider or cloud platform
3. Gather contact information from security.txt
4. Correlate with historical Shodan scan data

### Attack Surface Management

Maintain awareness of your external footprint:

1. Regularly scan your known asset inventory
2. Identify certificate mismatches or unexpected services
3. Track changes in WHOIS registration
4. Monitor for new open ports or services

## Command Reference

| Option | Description |
|--------|-------------|
| `targets` | IP addresses, hostnames, or CIDR networks |
| `-f, --file FILE` | File containing targets (one per line) |
| `-o, --output FILE` | Save results to JSON file |
| `-t, --threads N` | Concurrent target threads (default: 10, max: 50) |
| `--port-threads N` | Per-target port scan threads (default: 20) |
| `-q, --quiet` | Suppress info logging |
| `-v, --verbose` | Enable debug logging |
| `--json` | Output JSON to stdout |
| `--thorough` | Extended SSL port scan (27 ports) |
| `--shodan` | Enable Shodan enrichment |
| `--shodan-key KEY` | Shodan API key (alternative to env var) |
| `--ssl-ports PORTS` | Custom SSL ports (comma-separated) |
| `--banner-ports PORTS` | Custom banner ports (comma-separated) |
| `--no-parallel` | Disable parallel scanning |

## Contributing

Contributions are welcome! Areas of interest:

- Additional reconnaissance methods
- Output format options (CSV, HTML reports)
- Integration with other threat intelligence platforms
- Improved cloud provider detection
- AS number and BGP route analysis

## Disclaimer

This tool is intended for legitimate security research, asset verification, and defensive purposes. Always ensure you have proper authorization before scanning systems. Respect rate limits and terms of service for external APIs.

## License

MIT License - See LICENSE file for details.
