"""Destination policy, SSRF prevention, and scope enforcement for lab and authorized deployed targets."""
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

from app.utils.validators import is_url_in_scope

LAB_HOST = 'ase-lab'
LAB_IP = '172.30.250.3'
LAB_PORT = 8080
LAB_URL = 'http://ase-lab:8080'
ZAP_API = 'http://172.30.250.4:8080'

# Disallowed internal/private IP networks (SSRF prevention)
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local & cloud metadata (169.254.169.254)
    ipaddress.ip_network('172.16.0.0/12'),   # Private (except lab network)
    ipaddress.ip_network('192.0.0.0/24'),
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('198.18.0.0/15'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('224.0.0.0/4'),     # Multicast
    ipaddress.ip_network('240.0.0.0/4'),     # Reserved
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),        # Unique local IPv6
    ipaddress.ip_network('fe80::/10'),       # Link-local IPv6
]

LAB_CONTAINER_NETWORK = ipaddress.ip_network('172.30.250.0/24')


def is_lab_target(url: str) -> bool:
    """Return True if the target URL corresponds to the bundled ASE lab."""
    try:
        parsed = urlsplit(url)
        return parsed.hostname == LAB_HOST and (parsed.port == LAB_PORT or parsed.port is None)
    except Exception:
        return False


def validate_lab_target(url: str):
    """Verify target URL is the exact bundled lab."""
    if url not in {LAB_URL, LAB_URL + '/'}:
        raise PermissionError('Web scanning is restricted to the bundled ASE lab URL.')
    return LAB_URL


def resolve_lab():
    """Resolve and verify bundled lab address within the isolated container network."""
    addresses = {item[4][0] for item in socket.getaddrinfo(LAB_HOST, LAB_PORT, type=socket.SOCK_STREAM)}
    if addresses != {LAB_IP}:
        raise PermissionError('Lab DNS does not match the isolated network address.')
    return LAB_IP


def check_ssrf(ip_str: str, allow_lab: bool = False) -> None:
    """Ensure IP address does not target forbidden private or metadata ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as e:
        raise PermissionError(f'Target {ip_str!r} is not a valid IP address: {e}')

    if allow_lab and ip in LAB_CONTAINER_NETWORK:
        return

    if ip.is_loopback:
        raise PermissionError(f'Target IP {ip_str} is a loopback address (SSRF blocked).')
    if ip.is_link_local:
        raise PermissionError(f'Target IP {ip_str} is a link-local/cloud metadata address (SSRF blocked).')
    if ip.is_private and not (allow_lab and ip in LAB_CONTAINER_NETWORK):
        raise PermissionError(f'Target IP {ip_str} is in a private network range (SSRF blocked).')
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        raise PermissionError(f'Target IP {ip_str} is in a reserved/multicast range (SSRF blocked).')

    for net in FORBIDDEN_NETWORKS:
        if allow_lab and net == ipaddress.ip_network('172.16.0.0/12') and ip in LAB_CONTAINER_NETWORK:
            continue
        if ip in net:
            raise PermissionError(f'Target IP {ip_str} is in forbidden network {net} (SSRF blocked).')


def resolve_and_verify_destination(url: str, explicit_scope: str | None = None) -> str:
    """
    Validate target URL syntax, scope match, and resolve hostname to verify no SSRF.
    Returns the verified resolved IP address.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https'):
        raise PermissionError(f'Unsupported URL scheme: {parsed.scheme}. Only HTTP and HTTPS are permitted.')

    if parsed.username or parsed.password:
        raise PermissionError('Credentials in target URLs are forbidden.')

    hostname = parsed.hostname
    if not hostname:
        raise PermissionError('Target URL lacks a valid hostname.')

    # Check explicit scope if provided
    if explicit_scope:
        if not is_url_in_scope(url, explicit_scope):
            raise PermissionError(f'Target URL {url} is outside the authorized explicit scope: {explicit_scope}')

    # Special handling for lab
    if hostname == LAB_HOST:
        return resolve_lab()

    port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    try:
        addrinfo = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise PermissionError(f'Cannot resolve destination hostname "{hostname}": {str(e)}')

    resolved_ips = [item[4][0] for item in addrinfo]
    if not resolved_ips:
        raise PermissionError(f'No IP addresses resolved for hostname "{hostname}".')

    # Verify each resolved IP passes SSRF check
    for ip_str in resolved_ips:
        check_ssrf(ip_str, allow_lab=False)

    return resolved_ips[0]


def sanitize_endpoint(url: str, base_url: str, explicit_scope: str | None = None) -> str:
    """
    Sanitize crawler-discovered endpoint. Ensure it stays strictly within authorized scope
    and does not navigate to out-of-scope or private hosts. Discards credentials and fragments.
    """
    try:
        parsed = urlsplit(url)
        base = urlsplit(base_url)

        if parsed.scheme not in ('http', 'https'):
            raise ValueError('Invalid scheme')

        if parsed.username or parsed.password:
            raise ValueError('Credentials forbidden')

        if base.hostname == LAB_HOST:
            if parsed.hostname != LAB_HOST or (parsed.port and parsed.port != LAB_PORT):
                raise ValueError('Out-of-scope lab host')
        else:
            if parsed.hostname != base.hostname:
                if explicit_scope and not is_url_in_scope(url, explicit_scope):
                    raise ValueError('Out-of-scope crawler destination')

        path = parsed.path or '/'
        if len(path) > 512 or any(ord(c) < 32 for c in path):
            raise ValueError('Invalid path characters or length')

        netloc = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
        return urlunsplit((parsed.scheme, netloc, path, '', ''))
    except (ValueError, TypeError) as e:
        raise PermissionError(f'Scanner reported an out-of-scope or invalid endpoint: {str(e)}') from None


def sanitized_endpoint(url: str):
    """Backwards compatibility helper for lab scanning."""
    return sanitize_endpoint(url, LAB_URL, 'ase-lab')
