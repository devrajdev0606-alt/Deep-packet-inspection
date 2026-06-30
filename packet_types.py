"""
Data types and application classification
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict


class AppType(Enum):
    """Application types for classification"""
    UNKNOWN = 0
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    GOOGLE = auto()
    YOUTUBE = auto()
    FACEBOOK = auto()
    INSTAGRAM = auto()
    WHATSAPP = auto()
    TWITTER = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()
    GMAIL = auto()
    SLACK = auto()
    DISCORD = auto()
    TWITCH = auto()
    REDDIT = auto()


class ConnectionState(Enum):
    """Connection state"""
    ESTABLISHED = auto()
    CLOSED = auto()
    OPENING = auto()
    CLOSING = auto()


@dataclass
class FiveTuple:
    """Network five-tuple for connection identification"""
    src_ip: int = 0
    dst_ip: int = 0
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    
    def normalized(self):
        a = (self.src_ip, self.src_port)
        b = (self.dst_ip, self.dst_port)

        if a <= b:
            return (a, b, self.protocol)

        return (b, a, self.protocol)
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))
    
    def __eq__(self, other):
        if not isinstance(other, FiveTuple):
            return False
        return (self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)


@dataclass
class Connection:
    """Connection flow information"""
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    http_host: str = ""
    dns_query: str = ""
    state: ConnectionState = ConnectionState.ESTABLISHED
    packets_count: int = 0
    bytes_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    blocked: bool = False


class AppTypeClassifier:
    """Classify applications based on SNI/Host/DNS/Port"""
    
    @staticmethod
    def classify(sni: str = "", host: str = "", dns_query: str = "", 
                 src_port: int = 0, dst_port: int = 0, debug: bool = False) -> AppType:
        """Classify application type based on multiple signals"""
        
        # Priority 1: DNS queries (port 53)
        if dst_port == 53 or src_port == 53:
            if dns_query:
                result = AppTypeClassifier._classify_domain(dns_query)
                if result != AppType.UNKNOWN:
                    if debug:
                        print(f"  [DNS] Classified as {result.name} from query: {dns_query}")
                    return result
            if debug:
                print(f"  [DNS] No query, classified as DNS (port 53)")
            return AppType.DNS
        
        # Priority 2: SNI from TLS ClientHello
        if sni:
            result = AppTypeClassifier._classify_domain(sni)
            if result != AppType.UNKNOWN:
                if debug:
                    print(f"  [TLS SNI] Classified as {result.name} from: {sni}")
                return result
            if debug:
                print(f"  [TLS SNI] Could not classify domain: {sni}")
        
        # Priority 3: HTTP Host header
        if host:
            result = AppTypeClassifier._classify_domain(host)
            if result != AppType.UNKNOWN:
                if debug:
                    print(f"  [HTTP Host] Classified as {result.name} from: {host}")
                return result
            if debug:
                print(f"  [HTTP Host] Could not classify domain: {host}")
        
        # Priority 4: Port-based classification (fallback)
        if dst_port == 443 or src_port == 443:
            if debug:
                print(f"  [Port 443] Classified as HTTPS (no SNI found)")
            return AppType.HTTPS
        
        if dst_port == 80 or src_port == 80:
            if debug:
                print(f"  [Port 80] Classified as HTTP")
            return AppType.HTTP
        
        if debug:
            print(f"  [Unknown] No classification signals (ports: {src_port}/{dst_port})")
        return AppType.UNKNOWN
    
    @staticmethod
    def _classify_domain(domain: str) -> AppType:
        """Classify based on domain name"""
        if not domain:
            return AppType.UNKNOWN
        
        domain_lower = domain.lower()
        
        #  Youtube
        if any(keyword in domain_lower for keyword in ['youtube', 'ytimg', 'youtu.be', 'yt3.ggpht']):
            return AppType.YOUTUBE
        
        #Google
        if any(keyword in domain_lower for keyword in ['google', 'gstatic', 'googleapis', 'ggpht', 'gvt1']):
            return AppType.GOOGLE
        
        # Facebook/Meta
        if any(keyword in domain_lower for keyword in ['facebook', 'fbcdn', 'fb.com', 'fbsbx', 'meta.com']):
            return AppType.FACEBOOK
        
        # Instagram
        if any(keyword in domain_lower for keyword in ['instagram', 'cdninstagram']):
            return AppType.INSTAGRAM
        
        # WhatsApp
        if any(keyword in domain_lower for keyword in ['whatsapp', 'wa.me']):
            return AppType.WHATSAPP
        
        # Twitter/X
        if (
        domain_lower == "x.com" or
        domain_lower.endswith(".x.com") or
        "twitter.com" in domain_lower or
        "twimg.com" in domain_lower or
        domain_lower.endswith(".t.co") or
        domain_lower == "t.co"
        ):
            return AppType.TWITTER
        
        # Netflix
        if any(keyword in domain_lower for keyword in ['netflix', 'nflxvideo', 'nflximg']):
            return AppType.NETFLIX
        
        # Amazon
        if any(keyword in domain_lower for keyword in ['amazon', 'amazonaws', 'cloudfront', 'aws']):
            return AppType.AMAZON
        
        # Microsoft
        if any(keyword in domain_lower for keyword in ['microsoft', 'msn.com', 'office', 'azure', 'live.com', 'outlook', 'bing']):
            return AppType.MICROSOFT
        
        # Apple
        if any(keyword in domain_lower for keyword in ['apple', 'icloud', 'itunes', 'appstore']):
            return AppType.APPLE
        
        # GitHub
        if any(keyword in domain_lower for keyword in ['github', 'githubusercontent']):
            return AppType.GITHUB
        
        # Cloudflare
        if any(keyword in domain_lower for keyword in ['cloudflare', 'cf']):
            return AppType.CLOUDFLARE
        
        # Gmail
        if any(keyword in domain_lower for keyword in ['gmail']):
            return AppType.GMAIL
        
        # Slack
        if any(keyword in domain_lower for keyword in ['slack']):
            return AppType.SLACK
        
        # Discord
        if any(keyword in domain_lower for keyword in ['discord']):
            return AppType.DISCORD
        
        # Twitch
        if any(keyword in domain_lower for keyword in ['twitch']):
            return AppType.TWITCH
        
        # Reddit
        if any(keyword in domain_lower for keyword in ['reddit']):
            return AppType.REDDIT
        
        return AppType.UNKNOWN


def parse_ip_string(ip_str: str) -> int:
    """Convert dotted IP string to 32-bit integer"""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return 0
    
    try:
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
    except ValueError:
        return 0


def ip_int_to_string(ip_int: int) -> str:
    """Convert 32-bit integer to dotted IP string"""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
