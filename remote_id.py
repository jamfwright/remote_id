#!/usr/bin/env python3
"""
Remote Asset Identification Tool

Identifies ownership and accountability of internet-based assets through:
- DNS resolution
- WHOIS lookups
- SSL certificate inspection
- HTTP header analysis
- Banner grabbing
"""

import argparse
import json
import logging
import os
import socket
import ssl
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable

import dns.resolver
import dns.reversename
import requests
import shodan
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError

# Suppress only the specific urllib3 warning for unverified HTTPS
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_TIMEOUT = 2
DEFAULT_THREADS = 10
MAX_THREADS = 50
SSL_PORTS_DEFAULT = [443, 8443, 636, 993, 995, 465, 563, 585, 614, 684, 695, 989, 990]
SSL_PORTS_EXTENDED = [
    853,    # DNS over TLS (DoT)
    2083,   # cPanel SSL
    2087,   # WHM SSL
    2096,   # cPanel Webmail SSL
    2376,   # Docker daemon TLS
    3389,   # RDP (uses TLS)
    4443,   # Alternative HTTPS
    5061,   # SIP over TLS
    5671,   # AMQP over TLS (RabbitMQ)
    5986,   # WinRM HTTPS
    6443,   # Kubernetes API server
    8883,   # MQTT over SSL
    9443,   # Alternative HTTPS (WebSphere)
    10443,  # Alternative HTTPS
]
SSL_PORTS = SSL_PORTS_DEFAULT
BANNER_PORTS = [21, 22, 25, 80, 110]
HTTP_PORTS = [80, 443, 8080, 8443]
SMTP_PORTS = [25, 465, 587]
DNS_TIMEOUT = 3
SHODAN_API_KEY_ENV = 'SHODAN_API_KEY'

# Thread-safe print lock
print_lock = threading.Lock()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


@dataclass
class CertificateInfo:
    """SSL certificate information."""
    port: int
    common_name: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[dict] = None
    error: Optional[str] = None


@dataclass
class BannerInfo:
    """Service banner information."""
    port: int
    banner: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DnsRecords:
    """Container for DNS record information."""
    ptr: Optional[str] = None
    mx: list = field(default_factory=list)
    ns: list = field(default_factory=list)
    txt: list = field(default_factory=list)
    soa: Optional[dict] = None
    caa: list = field(default_factory=list)


@dataclass
class ShodanInfo:
    """Container for Shodan enrichment data."""
    organization: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    hostnames: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    services: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    last_update: Optional[str] = None
    os: Optional[str] = None
    error: Optional[str] = None


@dataclass
class AssetInfo:
    """Container for all gathered asset information."""
    target: str
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None
    whois_owner: Optional[str] = None
    whois_country: Optional[str] = None
    whois_cidr: Optional[str] = None
    whois_description: Optional[str] = None
    dns_records: Optional[DnsRecords] = None
    shodan: Optional[ShodanInfo] = None
    certificates: list = field(default_factory=list)
    banners: list = field(default_factory=list)
    smtp_banners: list = field(default_factory=list)
    http_headers: dict = field(default_factory=dict)
    redirects: list = field(default_factory=list)
    security_txt: Optional[str] = None
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        # Handle nested dataclasses
        if self.dns_records:
            result['dns_records'] = asdict(self.dns_records)
        if self.shodan:
            result['shodan'] = asdict(self.shodan)
        return result


def is_valid_ip(ip: str) -> bool:
    """Validate an IP address."""
    try:
        socket.inet_aton(ip.strip())
        return True
    except socket.error:
        return False


def is_cidr(target: str) -> bool:
    """Check if target is CIDR notation."""
    if '/' not in target:
        return False
    try:
        ip, prefix = target.split('/')
        return is_valid_ip(ip) and 0 <= int(prefix) <= 32
    except (ValueError, AttributeError):
        return False


def cidr_expand(network: str) -> list[str]:
    """
    Expand a CIDR network into individual IP addresses.

    Args:
        network: Network in CIDR notation (e.g., '192.168.1.0/24')

    Returns:
        List of IP addresses in the network (excluding network/broadcast)
    """
    try:
        ip, prefix = network.strip().split('/')
        prefix = int(prefix)

        if prefix < 0 or prefix > 32:
            raise ValueError(f"Invalid CIDR prefix: {prefix}")

        host_bits = 32 - prefix
        base_ip = struct.unpack('>I', socket.inet_aton(ip))[0]
        start = (base_ip >> host_bits) << host_bits
        end = start | ((1 << host_bits) - 1)

        # Skip network address (start) and broadcast address (end) for /31 and larger
        if prefix <= 30:
            return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start + 1, end)]
        else:
            # /31 and /32 networks - include all addresses
            return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end + 1)]

    except (ValueError, struct.error) as e:
        logger.error(f"Failed to expand CIDR {network}: {e}")
        return []


def dns_resolve(host: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[Optional[str], Optional[str]]:
    """
    Resolve hostname to IP address and get FQDN.

    Args:
        host: Hostname or IP to resolve
        timeout: Socket timeout in seconds

    Returns:
        Tuple of (ip_address, fqdn)
    """
    socket.setdefaulttimeout(timeout)
    host = host.strip()
    ip_address = None
    fqdn = None

    try:
        fqdn = socket.getfqdn(host)
    except socket.error as e:
        logger.debug(f"FQDN lookup failed for {host}: {e}")

    try:
        ip_address = socket.gethostbyname(host)
        logger.info(f"Resolved {host} -> {ip_address}")
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {host}: {e}")

    return ip_address, fqdn


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """
    Perform reverse DNS (PTR) lookup for an IP address.

    Args:
        ip: IP address to look up

    Returns:
        Hostname from PTR record, or None
    """
    if not ip:
        return None

    try:
        rev_name = dns.reversename.from_address(ip.strip())
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(rev_name, 'PTR')
        ptr = str(answers[0]).rstrip('.')
        logger.info(f"Reverse DNS: {ip} -> {ptr}")
        return ptr
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        logger.debug(f"No PTR record for {ip}")
    except dns.exception.Timeout:
        logger.debug(f"PTR lookup timeout for {ip}")
    except Exception as e:
        logger.debug(f"PTR lookup failed for {ip}: {e}")

    return None


def get_dns_records(domain: str) -> DnsRecords:
    """
    Retrieve various DNS records for a domain.

    Args:
        domain: Domain name to query

    Returns:
        DnsRecords dataclass with MX, NS, TXT, SOA, CAA records
    """
    records = DnsRecords()

    if not domain or is_valid_ip(domain):
        return records

    domain = domain.strip().lower()

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    # MX Records
    try:
        answers = resolver.resolve(domain, 'MX')
        records.mx = [
            {'priority': r.preference, 'host': str(r.exchange).rstrip('.')}
            for r in answers
        ]
        logger.info(f"DNS MX for {domain}: {len(records.mx)} records")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        logger.debug(f"MX lookup timeout for {domain}")
    except Exception as e:
        logger.debug(f"MX lookup failed for {domain}: {e}")

    # NS Records
    try:
        answers = resolver.resolve(domain, 'NS')
        records.ns = [str(r).rstrip('.') for r in answers]
        logger.info(f"DNS NS for {domain}: {records.ns}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        logger.debug(f"NS lookup timeout for {domain}")
    except Exception as e:
        logger.debug(f"NS lookup failed for {domain}: {e}")

    # TXT Records (SPF, DKIM, DMARC, etc.)
    try:
        answers = resolver.resolve(domain, 'TXT')
        records.txt = [str(r).strip('"') for r in answers]
        logger.info(f"DNS TXT for {domain}: {len(records.txt)} records")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        logger.debug(f"TXT lookup timeout for {domain}")
    except Exception as e:
        logger.debug(f"TXT lookup failed for {domain}: {e}")

    # DMARC Record (specific subdomain)
    try:
        answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for r in answers:
            txt = str(r).strip('"')
            if txt.startswith('v=DMARC'):
                records.txt.append(f"DMARC: {txt}")
                logger.info(f"DMARC found for {domain}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception:
        pass

    # SOA Record
    try:
        answers = resolver.resolve(domain, 'SOA')
        soa = answers[0]
        records.soa = {
            'mname': str(soa.mname).rstrip('.'),
            'rname': str(soa.rname).rstrip('.').replace('.', '@', 1),  # Convert to email format
            'serial': soa.serial
        }
        logger.info(f"DNS SOA for {domain}: {records.soa['mname']}")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        logger.debug(f"SOA lookup timeout for {domain}")
    except Exception as e:
        logger.debug(f"SOA lookup failed for {domain}: {e}")

    # CAA Records
    try:
        answers = resolver.resolve(domain, 'CAA')
        records.caa = [
            {'flags': r.flags, 'tag': r.tag.decode(), 'value': r.value.decode()}
            for r in answers
        ]
        logger.info(f"DNS CAA for {domain}: {len(records.caa)} records")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        logger.debug(f"CAA lookup timeout for {domain}")
    except Exception as e:
        logger.debug(f"CAA lookup failed for {domain}: {e}")

    return records


def get_security_txt(host: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[str]:
    """
    Fetch security.txt from a host.

    Args:
        host: Hostname or IP
        timeout: Request timeout

    Returns:
        Contents of security.txt if found, None otherwise
    """
    urls = [
        f"https://{host.strip()}/.well-known/security.txt",
        f"https://{host.strip()}/security.txt",
        f"http://{host.strip()}/.well-known/security.txt",
        f"http://{host.strip()}/security.txt",
    ]

    headers = {"User-Agent": USER_AGENT}

    for url in urls:
        try:
            response = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=timeout,
                allow_redirects=True
            )
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                # Verify it's text content
                if 'text' in content_type or len(response.text) < 10000:
                    text = response.text.strip()
                    # Basic validation - should contain Contact:
                    if 'Contact:' in text or 'contact:' in text.lower():
                        logger.info(f"Found security.txt at {url}")
                        return text
        except requests.exceptions.RequestException:
            continue

    return None


def grab_smtp_banner(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> BannerInfo:
    """
    Grab SMTP banner from a mail server.

    Args:
        host: Hostname or IP
        port: SMTP port (25, 465, 587)
        timeout: Socket timeout

    Returns:
        BannerInfo dataclass with SMTP banner
    """
    banner_info = BannerInfo(port=port)

    try:
        if port == 465:
            # SMTPS - SSL wrapped
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host.strip(), port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host.strip()) as ssock:
                    ssock.settimeout(timeout)
                    banner = ssock.recv(1024)
                    banner_info.banner = banner.decode('utf-8', errors='replace').strip()
        else:
            # Plain SMTP (25, 587)
            with socket.create_connection((host.strip(), port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = sock.recv(1024)
                banner_info.banner = banner.decode('utf-8', errors='replace').strip()

        if banner_info.banner:
            logger.info(f"SMTP banner on {host}:{port}: {banner_info.banner[:60]}...")

    except socket.timeout:
        banner_info.error = "Connection timeout"
    except ConnectionRefusedError:
        banner_info.error = "Connection refused"
    except ssl.SSLError as e:
        banner_info.error = f"SSL error: {e}"
    except OSError as e:
        banner_info.error = str(e)

    return banner_info


def whois_lookup(ip: str) -> dict:
    """
    Perform WHOIS/RDAP lookup for an IP address.

    Args:
        ip: IP address to look up

    Returns:
        Dictionary with owner, country, cidr, and description
    """
    result = {
        'owner': None,
        'country': None,
        'cidr': None,
        'description': None
    }

    if not ip:
        return result

    try:
        obj = IPWhois(ip.strip())
        rdap_result = obj.lookup_rdap(depth=1)

        network = rdap_result.get('network', {})
        result['owner'] = network.get('name')
        result['country'] = network.get('country')
        result['cidr'] = network.get('cidr')

        # Get description from remarks if available
        remarks = network.get('remarks', [])
        if remarks and isinstance(remarks, list):
            result['description'] = remarks[0].get('description') if remarks[0] else None

        logger.info(f"WHOIS: {ip} owned by {result['owner']} ({result['country']})")

    except IPDefinedError:
        logger.debug(f"WHOIS: {ip} is a private/reserved address")
        result['owner'] = "Private/Reserved Address"
    except ASNRegistryError as e:
        logger.warning(f"WHOIS ASN registry error for {ip}: {e}")
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {ip}: {e}")

    return result


def shodan_lookup(ip: str, api_key: str) -> ShodanInfo:
    """
    Query Shodan for information about an IP address.

    Args:
        ip: IP address to look up
        api_key: Shodan API key

    Returns:
        ShodanInfo dataclass with enrichment data
    """
    info = ShodanInfo()

    if not ip or not api_key:
        if not api_key:
            info.error = "No API key provided"
        return info

    try:
        api = shodan.Shodan(api_key)
        result = api.host(ip.strip())

        # Organization/Network info
        info.organization = result.get('org')
        info.isp = result.get('isp')
        info.asn = result.get('asn')
        info.country = result.get('country_name')
        info.city = result.get('city')
        info.os = result.get('os')
        info.last_update = result.get('last_update')

        # Hostnames and domains
        info.hostnames = result.get('hostnames', [])
        info.domains = result.get('domains', [])

        # Open ports
        info.open_ports = result.get('ports', [])

        # Tags (e.g., 'cloud', 'vpn', 'self-signed')
        info.tags = result.get('tags', [])

        # Vulnerabilities
        info.vulns = list(result.get('vulns', {}).keys()) if result.get('vulns') else []

        # Services - extract key info from each service
        services = []
        for item in result.get('data', []):
            service = {
                'port': item.get('port'),
                'transport': item.get('transport', 'tcp'),
                'product': item.get('product'),
                'version': item.get('version'),
                'module': item.get('_shodan', {}).get('module'),
            }
            # Add banner preview
            banner = item.get('data', '')
            if banner:
                service['banner_preview'] = banner[:100].replace('\n', ' ').replace('\r', '')

            # SSL info if present
            ssl_info = item.get('ssl', {})
            if ssl_info:
                cert = ssl_info.get('cert', {})
                service['ssl_cn'] = cert.get('subject', {}).get('CN')
                service['ssl_issuer'] = cert.get('issuer', {}).get('O')

            services.append(service)

        info.services = services

        logger.info(f"Shodan: {ip} - {info.organization}, {len(info.open_ports)} ports, {len(info.vulns)} vulns")

    except shodan.APIError as e:
        error_msg = str(e)
        if 'No information available' in error_msg:
            info.error = "No Shodan data available for this IP"
            logger.debug(f"Shodan: No data for {ip}")
        elif 'Invalid API key' in error_msg:
            info.error = "Invalid Shodan API key"
            logger.error("Shodan: Invalid API key")
        else:
            info.error = f"Shodan API error: {error_msg}"
            logger.warning(f"Shodan API error for {ip}: {e}")
    except Exception as e:
        info.error = f"Shodan lookup failed: {e}"
        logger.warning(f"Shodan lookup failed for {ip}: {e}")

    return info


def get_ssl_certificate(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> CertificateInfo:
    """
    Retrieve SSL certificate information from a host:port.

    Args:
        host: Hostname or IP
        port: Port number
        timeout: Connection timeout

    Returns:
        CertificateInfo dataclass
    """
    cert_info = CertificateInfo(port=port)

    try:
        # First try with verification to get parsed cert
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((host.strip(), port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host.strip()) as ssock:
                cert = ssock.getpeercert(binary_form=False)

                if cert:
                    cert_info.subject = dict(x[0] for x in cert.get('subject', []))
                    cert_info.common_name = cert_info.subject.get('commonName')

                    issuer_tuples = cert.get('issuer', [])
                    if issuer_tuples:
                        issuer_dict = dict(x[0] for x in issuer_tuples)
                        cert_info.issuer = issuer_dict.get('organizationName')

                    logger.info(f"SSL cert on {host}:{port} - CN: {cert_info.common_name}")

    except ssl.SSLCertVerificationError:
        # Cert failed verification - try to get info anyway via OpenSSL-style parsing
        try:
            import subprocess
            result = subprocess.run(
                ['openssl', 's_client', '-connect', f'{host.strip()}:{port}', '-servername', host.strip()],
                capture_output=True, text=True, timeout=timeout, input=''
            )
            # Parse the certificate subject from openssl output
            for line in result.stdout.split('\n'):
                if 'subject=' in line.lower():
                    cert_info.subject = {'raw': line}
                    # Extract CN if present
                    if 'CN=' in line or 'CN =' in line:
                        cn_part = line.split('CN')[-1]
                        cn = cn_part.split('=')[1].split(',')[0].split('/')[0].strip()
                        cert_info.common_name = cn
                        logger.info(f"SSL cert on {host}:{port} - CN: {cert_info.common_name}")
                elif 'issuer=' in line.lower():
                    if 'O=' in line or 'O =' in line:
                        o_part = line.split('O')[-1]
                        cert_info.issuer = o_part.split('=')[1].split(',')[0].split('/')[0].strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            cert_info.error = f"Certificate present but unverified: {e}"
            logger.debug(f"Could not parse unverified cert on {host}:{port}")

    except ssl.SSLError as e:
        cert_info.error = f"SSL error: {e}"
        logger.debug(f"SSL error on {host}:{port}: {e}")
    except socket.timeout:
        cert_info.error = "Connection timeout"
    except ConnectionRefusedError:
        cert_info.error = "Connection refused"
    except OSError as e:
        cert_info.error = str(e)
        logger.debug(f"Connection failed to {host}:{port}: {e}")

    return cert_info


def get_http_info(host: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT) -> tuple[dict, list]:
    """
    Get HTTP headers and follow redirects.

    Args:
        host: Hostname or IP
        port: Port number
        timeout: Request timeout

    Returns:
        Tuple of (headers_dict, redirect_list)
    """
    headers_result = {}
    redirects = []

    scheme = 'https' if port in [443, 8443] else 'http'
    url = f"{scheme}://{host.strip()}"
    if port not in [80, 443]:
        url = f"{url}:{port}"

    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    try:
        response = requests.get(
            url,
            headers=request_headers,
            verify=False,
            timeout=timeout,
            allow_redirects=True
        )

        headers_result = dict(response.headers)

        # Track redirect chain
        for r in response.history:
            redirects.append(r.url)
        if response.history:
            redirects.append(response.url)  # Final destination

        logger.info(f"HTTP {response.status_code} from {url}")

    except requests.exceptions.Timeout:
        logger.debug(f"HTTP timeout connecting to {url}")
    except requests.exceptions.ConnectionError as e:
        logger.debug(f"HTTP connection error to {url}: {e}")
    except requests.exceptions.RequestException as e:
        logger.warning(f"HTTP request failed for {url}: {e}")

    return headers_result, redirects


def grab_banner(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> BannerInfo:
    """
    Grab service banner from a port.

    Args:
        host: Hostname or IP
        port: Port number
        timeout: Socket timeout

    Returns:
        BannerInfo dataclass
    """
    banner_info = BannerInfo(port=port)

    try:
        with socket.create_connection((host.strip(), port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            # Some services need a prompt
            if port == 80:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = sock.recv(1024)
            banner_info.banner = banner.decode('utf-8', errors='replace').strip()

            if banner_info.banner:
                logger.info(f"Banner on {host}:{port}: {banner_info.banner[:50]}...")

    except socket.timeout:
        banner_info.error = "Connection timeout"
    except ConnectionRefusedError:
        banner_info.error = "Connection refused"
    except OSError as e:
        banner_info.error = str(e)

    return banner_info


def analyze_target(
    target: str,
    ssl_ports: list = None,
    banner_ports: list = None,
    shodan_api_key: str = None,
    port_threads: int = 20
) -> AssetInfo:
    """
    Perform full analysis on a target.

    Args:
        target: IP address, hostname, or domain to analyze
        ssl_ports: List of ports to check for SSL certs
        banner_ports: List of ports to grab banners from
        shodan_api_key: Optional Shodan API key for enrichment
        port_threads: Number of threads for parallel port scanning

    Returns:
        AssetInfo dataclass with all gathered information
    """
    ssl_ports = ssl_ports or SSL_PORTS
    banner_ports = banner_ports or BANNER_PORTS

    asset = AssetInfo(target=target.strip())

    logger.info(f"\n{'='*60}")
    logger.info(f"Analyzing: {target}")
    logger.info('='*60)

    # DNS Resolution
    asset.ip_address, asset.fqdn = dns_resolve(target)

    # If we couldn't resolve and it's not an IP, we can't continue some checks
    lookup_ip = asset.ip_address
    if not lookup_ip and is_valid_ip(target):
        lookup_ip = target.strip()
        asset.ip_address = lookup_ip

    # Reverse DNS (PTR) lookup
    if lookup_ip:
        ptr = reverse_dns_lookup(lookup_ip)
        if ptr and ptr != asset.fqdn:
            # Update FQDN if PTR gives better result
            if not asset.fqdn or asset.fqdn == target:
                asset.fqdn = ptr

    # DNS Records (MX, NS, TXT, SOA, CAA)
    asset.dns_records = get_dns_records(target)
    if lookup_ip:
        asset.dns_records.ptr = reverse_dns_lookup(lookup_ip)

    # WHOIS Lookup
    if lookup_ip:
        whois_result = whois_lookup(lookup_ip)
        asset.whois_owner = whois_result['owner']
        asset.whois_country = whois_result['country']
        asset.whois_cidr = whois_result['cidr']
        asset.whois_description = whois_result['description']
    else:
        asset.errors.append("Could not resolve IP for WHOIS lookup")

    # Shodan Enrichment
    if lookup_ip and shodan_api_key:
        asset.shodan = shodan_lookup(lookup_ip, shodan_api_key)

    # Parallel port scanning for SSL, HTTP, SMTP, and banners
    scan_target = lookup_ip or target

    with ThreadPoolExecutor(max_workers=port_threads) as executor:
        # Submit all SSL certificate checks
        ssl_futures = {
            executor.submit(get_ssl_certificate, target, port): ('ssl', port)
            for port in ssl_ports
        }

        # Submit all HTTP checks
        http_futures = {
            executor.submit(get_http_info, target, port): ('http', port)
            for port in HTTP_PORTS
        }

        # Submit all SMTP banner checks
        smtp_futures = {
            executor.submit(grab_smtp_banner, scan_target, port): ('smtp', port)
            for port in SMTP_PORTS
        }

        # Submit all general banner checks
        banner_futures = {
            executor.submit(grab_banner, scan_target, port): ('banner', port)
            for port in banner_ports
        }

        # Combine all futures
        all_futures = {**ssl_futures, **http_futures, **smtp_futures, **banner_futures}

        # Collect results as they complete
        for future in as_completed(all_futures):
            scan_type, port = all_futures[future]
            try:
                result = future.result()

                if scan_type == 'ssl':
                    cert = result
                    if cert.common_name or cert.error != "Connection refused":
                        asset.certificates.append(asdict(cert))

                elif scan_type == 'http':
                    headers, redirects = result
                    if headers:
                        asset.http_headers[str(port)] = headers
                    if redirects:
                        asset.redirects.extend(redirects)

                elif scan_type == 'smtp':
                    smtp_banner = result
                    if smtp_banner.banner or smtp_banner.error not in ["Connection refused", "Connection timeout"]:
                        asset.smtp_banners.append(asdict(smtp_banner))

                elif scan_type == 'banner':
                    banner = result
                    if banner.banner or banner.error not in ["Connection refused", "Connection timeout"]:
                        asset.banners.append(asdict(banner))

            except Exception as e:
                logger.debug(f"Error scanning {scan_type} port {port}: {e}")

    # Remove duplicate redirects while preserving order
    asset.redirects = list(dict.fromkeys(asset.redirects))

    # Security.txt (done after HTTP to avoid conflicts)
    asset.security_txt = get_security_txt(target)

    return asset


def print_report(asset: AssetInfo) -> None:
    """Print a human-readable report of the asset analysis (thread-safe)."""
    lines = []
    lines.append(f"\n{'='*70}")
    lines.append(f"ASSET IDENTIFICATION REPORT: {asset.target}")
    lines.append('='*70)

    lines.append(f"\n[DNS/Network]")
    lines.append(f"  Target:     {asset.target}")
    lines.append(f"  IP Address: {asset.ip_address or 'N/A'}")
    lines.append(f"  FQDN:       {asset.fqdn or 'N/A'}")
    if asset.dns_records and asset.dns_records.ptr:
        lines.append(f"  PTR:        {asset.dns_records.ptr}")

    lines.append(f"\n[WHOIS Information]")
    lines.append(f"  Owner:      {asset.whois_owner or 'N/A'}")
    lines.append(f"  Country:    {asset.whois_country or 'N/A'}")
    lines.append(f"  CIDR:       {asset.whois_cidr or 'N/A'}")

    # DNS Records
    if asset.dns_records:
        dns = asset.dns_records
        if dns.ns or dns.mx or dns.txt or dns.soa:
            lines.append(f"\n[DNS Records]")

            if dns.ns:
                lines.append(f"  Nameservers:")
                for ns in dns.ns[:4]:  # Limit to 4
                    lines.append(f"    - {ns}")

            if dns.mx:
                lines.append(f"  Mail Servers:")
                for mx in sorted(dns.mx, key=lambda x: x['priority'])[:4]:
                    lines.append(f"    - [{mx['priority']}] {mx['host']}")

            if dns.soa:
                lines.append(f"  SOA:")
                lines.append(f"    - Primary NS: {dns.soa['mname']}")
                lines.append(f"    - Admin:      {dns.soa['rname']}")

            if dns.txt:
                lines.append(f"  TXT Records:")
                for txt in dns.txt[:6]:  # Limit to 6
                    # Truncate long TXT records
                    txt_preview = txt[:80] + '...' if len(txt) > 80 else txt
                    lines.append(f"    - {txt_preview}")

            if dns.caa:
                lines.append(f"  CAA Records:")
                for caa in dns.caa:
                    lines.append(f"    - {caa['tag']}: {caa['value']}")

    if asset.certificates:
        lines.append(f"\n[SSL Certificates]")
        for cert in asset.certificates:
            if cert.get('common_name'):
                lines.append(f"  Port {cert['port']}: CN={cert['common_name']}, Issuer={cert.get('issuer', 'N/A')}")

    if asset.redirects:
        lines.append(f"\n[HTTP Redirects]")
        for url in asset.redirects:
            lines.append(f"  -> {url}")

    if asset.http_headers:
        lines.append(f"\n[Notable HTTP Headers]")
        interesting_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version',
                              'X-Generator', 'Via', 'X-Cache']
        for port, headers in asset.http_headers.items():
            for h in interesting_headers:
                if h in headers:
                    lines.append(f"  Port {port} - {h}: {headers[h]}")

    if asset.security_txt:
        lines.append(f"\n[Security.txt]")
        # Parse key fields from security.txt
        for line in asset.security_txt.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                if any(line.startswith(f) for f in ['Contact:', 'Expires:', 'Encryption:', 'Policy:', 'Hiring:']):
                    lines.append(f"  {line}")

    if asset.smtp_banners:
        lines.append(f"\n[SMTP Banners]")
        for banner in asset.smtp_banners:
            if banner.get('banner'):
                banner_preview = banner['banner'][:100].replace('\n', ' ').replace('\r', '')
                lines.append(f"  Port {banner['port']}: {banner_preview}")

    if asset.banners:
        lines.append(f"\n[Service Banners]")
        for banner in asset.banners:
            if banner.get('banner'):
                banner_preview = banner['banner'][:100].replace('\n', ' ')
                lines.append(f"  Port {banner['port']}: {banner_preview}")

    # Shodan Enrichment Data
    if asset.shodan and not asset.shodan.error:
        shodan = asset.shodan
        lines.append(f"\n[Shodan Intelligence]")
        if shodan.organization:
            lines.append(f"  Organization: {shodan.organization}")
        if shodan.isp:
            lines.append(f"  ISP:          {shodan.isp}")
        if shodan.asn:
            lines.append(f"  ASN:          {shodan.asn}")
        if shodan.country or shodan.city:
            location = ', '.join(filter(None, [shodan.city, shodan.country]))
            lines.append(f"  Location:     {location}")
        if shodan.os:
            lines.append(f"  OS:           {shodan.os}")
        if shodan.hostnames:
            lines.append(f"  Hostnames:    {', '.join(shodan.hostnames[:5])}")
        if shodan.domains:
            lines.append(f"  Domains:      {', '.join(shodan.domains[:5])}")
        if shodan.open_ports:
            ports_str = ', '.join(str(p) for p in sorted(shodan.open_ports)[:15])
            lines.append(f"  Open Ports:   {ports_str}")
        if shodan.tags:
            lines.append(f"  Tags:         {', '.join(shodan.tags)}")
        if shodan.vulns:
            lines.append(f"  Vulns ({len(shodan.vulns)}):")
            for vuln in shodan.vulns[:10]:
                lines.append(f"    - {vuln}")
        if shodan.services:
            lines.append(f"  Services:")
            for svc in shodan.services[:8]:
                port = svc.get('port', '?')
                product = svc.get('product') or svc.get('module') or 'unknown'
                version = svc.get('version', '')
                svc_str = f"    - {port}/{svc.get('transport', 'tcp')}: {product}"
                if version:
                    svc_str += f" {version}"
                if svc.get('ssl_cn'):
                    svc_str += f" (SSL: {svc['ssl_cn']})"
                lines.append(svc_str)
        if shodan.last_update:
            lines.append(f"  Last Scan:    {shodan.last_update}")
    elif asset.shodan and asset.shodan.error:
        lines.append(f"\n[Shodan]")
        lines.append(f"  {asset.shodan.error}")

    if asset.errors:
        lines.append(f"\n[Errors]")
        for error in asset.errors:
            lines.append(f"  - {error}")

    lines.append(f"\n{'='*70}\n")

    # Thread-safe print
    with print_lock:
        print('\n'.join(lines))


def load_targets_from_file(filepath: str) -> list[str]:
    """Load targets from a file, one per line."""
    targets = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        logger.info(f"Loaded {len(targets)} targets from {filepath}")
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
    except IOError as e:
        logger.error(f"Error reading file {filepath}: {e}")
    return targets


def analyze_target_wrapper(
    target: str,
    ssl_ports: list,
    banner_ports: list,
    shodan_api_key: str = None,
    print_results: bool = True,
    port_threads: int = 20
) -> AssetInfo:
    """
    Wrapper for analyze_target that optionally prints results.
    Used by ThreadPoolExecutor for concurrent scanning.
    """
    asset = analyze_target(target, ssl_ports, banner_ports, shodan_api_key, port_threads)
    if print_results:
        print_report(asset)
    return asset


def run_concurrent_scan(
    targets: list[str],
    ssl_ports: list,
    banner_ports: list,
    num_threads: int,
    shodan_api_key: str = None,
    print_results: bool = True,
    progress_callback: Callable[[int, int], None] = None,
    port_threads: int = 20
) -> list[AssetInfo]:
    """
    Run concurrent scans on multiple targets.

    Args:
        targets: List of targets to scan
        ssl_ports: List of SSL ports to check
        banner_ports: List of banner ports to check
        num_threads: Number of concurrent threads
        shodan_api_key: Optional Shodan API key for enrichment
        print_results: Whether to print reports as they complete
        progress_callback: Optional callback(completed, total) for progress updates
        port_threads: Number of threads for parallel port scanning within each target

    Returns:
        List of AssetInfo results
    """
    results = []
    total = len(targets)
    completed = 0

    logger.info(f"Starting concurrent scan of {total} targets with {num_threads} threads")

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit all tasks
        future_to_target = {
            executor.submit(
                analyze_target_wrapper,
                target,
                ssl_ports,
                banner_ports,
                shodan_api_key,
                print_results,
                port_threads
            ): target
            for target in targets
        }

        # Collect results as they complete
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            completed += 1

            try:
                asset = future.result()
                results.append(asset)

                if progress_callback:
                    progress_callback(completed, total)
                else:
                    logger.info(f"Progress: {completed}/{total} targets completed")

            except Exception as e:
                logger.error(f"Error scanning {target}: {e}")
                # Create an error result
                error_asset = AssetInfo(target=target)
                error_asset.errors.append(f"Scan failed: {e}")
                results.append(error_asset)

    logger.info(f"Scan complete: {len(results)} targets analyzed")
    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Identify ownership and accountability of internet-based assets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 8.8.8.8                              # Analyze single IP
  %(prog)s example.com                          # Analyze domain
  %(prog)s 8.8.8.8 1.1.1.1 google.com           # Analyze multiple targets
  %(prog)s 192.168.1.0/28                       # Analyze CIDR range
  %(prog)s -f targets.txt                       # Analyze targets from file
  %(prog)s 8.8.8.8 -f more_targets.txt          # Combine CLI args and file
  %(prog)s example.com -o results.json          # Output to JSON file
  %(prog)s -f targets.txt -t 20                 # Scan with 20 concurrent threads
  %(prog)s 8.8.8.8 --shodan                     # Include Shodan enrichment
  %(prog)s example.com --thorough               # Extended SSL port scan (27 ports)
  %(prog)s -f targets.txt --port-threads 30    # Increase per-target parallelism

Environment Variables:
  SHODAN_API_KEY    Your Shodan API key for enrichment data
        """
    )

    parser.add_argument('targets', nargs='*', help='IP addresses, hostnames, or CIDR networks')
    parser.add_argument('-f', '--file', action='append', dest='files', metavar='FILE',
                        help='File containing targets (one per line). Can be specified multiple times.')
    parser.add_argument('-o', '--output', help='Output results to JSON file')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS,
                        help=f'Number of concurrent threads (default: {DEFAULT_THREADS}, max: {MAX_THREADS})')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress info logging')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging')
    parser.add_argument('--ssl-ports', type=str, help='Comma-separated list of SSL ports to check')
    parser.add_argument('--banner-ports', type=str, help='Comma-separated list of banner ports')
    parser.add_argument('--json', action='store_true', help='Output results as JSON to stdout')
    parser.add_argument('--no-parallel', action='store_true', help='Disable parallel scanning (sequential mode)')
    parser.add_argument('--shodan', action='store_true',
                        help=f'Enable Shodan enrichment (requires {SHODAN_API_KEY_ENV} environment variable)')
    parser.add_argument('--shodan-key', type=str, metavar='KEY',
                        help='Shodan API key (alternative to environment variable)')
    parser.add_argument('--thorough', action='store_true',
                        help='Include extended SSL ports (DoT, Kubernetes, Docker, RDP, etc.)')
    parser.add_argument('--port-threads', type=int, default=20,
                        help='Number of threads for parallel port scanning within each target (default: 20)')

    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    # Handle Shodan API key
    shodan_api_key = None
    if args.shodan or args.shodan_key:
        shodan_api_key = args.shodan_key or os.environ.get(SHODAN_API_KEY_ENV)
        if not shodan_api_key:
            logger.warning(f"Shodan enabled but no API key found. Set {SHODAN_API_KEY_ENV} or use --shodan-key")
        else:
            logger.info("Shodan enrichment enabled")

    # Validate thread count
    num_threads = min(args.threads, MAX_THREADS)
    if args.threads > MAX_THREADS:
        logger.warning(f"Thread count capped at {MAX_THREADS}")

    # Parse custom ports if provided
    ssl_ports = SSL_PORTS_DEFAULT
    banner_ports = BANNER_PORTS

    # Use extended SSL ports if --thorough is specified
    if args.thorough:
        ssl_ports = SSL_PORTS_DEFAULT + SSL_PORTS_EXTENDED
        logger.info(f"Thorough mode: scanning {len(ssl_ports)} SSL ports")

    if args.ssl_ports:
        ssl_ports = [int(p.strip()) for p in args.ssl_ports.split(',')]
    if args.banner_ports:
        banner_ports = [int(p.strip()) for p in args.banner_ports.split(',')]

    port_threads = args.port_threads

    # Collect targets from all sources
    targets = []

    # Add targets from command line arguments
    if args.targets:
        targets.extend(args.targets)
        logger.info(f"Added {len(args.targets)} targets from command line")

    # Add targets from file(s)
    if args.files:
        for filepath in args.files:
            file_targets = load_targets_from_file(filepath)
            targets.extend(file_targets)

    # Check if we have any targets
    if not targets:
        parser.print_help()
        print("\nError: Please provide targets via command line or file (-f)")
        sys.exit(1)

    # Expand any CIDR notations and deduplicate
    expanded_targets = []
    seen = set()
    for target in targets:
        target = target.strip()
        if not target:
            continue
        if is_cidr(target):
            cidr_ips = cidr_expand(target)
            logger.info(f"Expanded {target} to {len(cidr_ips)} addresses")
            for ip in cidr_ips:
                if ip not in seen:
                    seen.add(ip)
                    expanded_targets.append(ip)
        else:
            if target not in seen:
                seen.add(target)
                expanded_targets.append(target)
    targets = expanded_targets
    logger.info(f"Total unique targets: {len(targets)}")

    if not targets:
        logger.error("No valid targets to analyze")
        sys.exit(1)

    # Analyze targets
    print_results = not args.json

    if args.no_parallel or len(targets) == 1:
        # Sequential mode
        results = []
        for target in targets:
            asset = analyze_target(target, ssl_ports, banner_ports, shodan_api_key, port_threads)
            results.append(asset)
            if print_results:
                print_report(asset)
    else:
        # Concurrent mode
        results = run_concurrent_scan(
            targets,
            ssl_ports,
            banner_ports,
            num_threads,
            shodan_api_key,
            print_results,
            port_threads=port_threads
        )

    # Output results
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump([r.to_dict() for r in results], f, indent=2)
            logger.info(f"Results written to {args.output}")
        except IOError as e:
            logger.error(f"Failed to write output file: {e}")
            sys.exit(1)

    return results


if __name__ == '__main__':
    main()
