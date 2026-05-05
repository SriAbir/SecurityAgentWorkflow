import ipaddress
import socket
from urllib.parse import urlparse

def is_safe_url(url: str) -> bool:
    """Validate URL to prevent SSRF attacks."""
    parsed = urlparse(url)
    
    # Only allow http/https
    if parsed.scheme not in ('http', 'https'):
        return False
    
    # Resolve hostname
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except (socket.gaierror, ValueError):
        return False
    
    # Block private/internal addresses
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    
    # Block cloud metadata IPs
    if str(ip).startswith('169.254.'):
        return False
    
    return True

# Apply before requests.get()
if not is_safe_url(document):
    raise ValueError(f"Blocked SSRF attempt to {document}")
response = requests.get(document, timeout=10.0)