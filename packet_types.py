"""
Data types and application classification
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict


class AppType(Enum):
    """Application types for classification"""
    UNKNOWN = 0
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
    DNS = auto()


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
    """Classify applications based on SNI/Host/DNS"""
    
    @staticmethod
    def classify(sni: str = "", host: str = "", dns_query: str = "", 
                 src_port: int = 0, dst_port: int = 0) -> AppType:
        """Classify application type based on SNI, HTTP Host, or DNS query"""
        
        # First check DNS queries
        if dns_query:
            domain = dns_query.lower()
            result = AppTypeClassifier._classify_domain(domain)
            if result != AppType.UNKNOWN:
                return result
        
        # Then check SNI
        if sni:
            domain = sni.lower()
            result = AppTypeClassifier._classify_domain(domain)
            if result != AppType.UNKNOWN:
                return result
        
        # Then check HTTP Host
        if host:
            domain = host.lower()
            result = AppTypeClassifier._classify_domain(domain)
            if result != AppType.UNKNOWN:
                return result
        
        # Check by port if no domain info
        if dst_port == 53 or src_port == 53:
            return AppType.DNS
        
        return AppType.UNKNOWN
    
    @staticmethod
    def _classify_domain(domain: str) -> AppType:
        """Classify based on domain name"""
        if not domain:
            return AppType.UNKNOWN
        
        # Google (including YouTube, which is owned by Google)
        if any(keyword in domain for keyword in ['google', 'gstatic', 'googleapis', 'ggpht', 'gvt1']):
            return AppType.GOOGLE
        
        # YouTube
        if any(keyword in domain for keyword in ['youtube', 'ytimg', 'youtu.be', 'yt3.ggpht']):
            return AppType.YOUTUBE
        
        # Facebook/Meta
        if any(keyword in domain for keyword in ['facebook', 'fbcdn', 'fb.com', 'fbsbx', 'meta.com']):
            return AppType.FACEBOOK
        
        # Instagram
        if any(keyword in domain for keyword in ['instagram', 'cdninstagram']):
            return AppType.INSTAGRAM
        
        # WhatsApp
        if any(keyword in domain for keyword in ['whatsapp', 'wa.me']):
            return AppType.WHATSAPP
        
        # Twitter/X
        if any(keyword in domain for keyword in ['twitter', 'twimg', 'x.com', 't.co']):
            return AppType.TWITTER
        
        # Netflix
        if any(keyword in domain for keyword in ['netflix', 'nflxvideo', 'nflximg']):
            return AppType.NETFLIX
        
        # Amazon
        if any(keyword in domain for keyword in ['amazon', 'amazonaws', 'cloudfront', 'aws']):
            return AppType.AMAZON
        
        # Microsoft
        if any(keyword in domain for keyword in ['microsoft', 'msn.com', 'office', 'azure', 'live.com', 'outlook', 'bing']):
            return AppType.MICROSOFT
        
        # Apple
        if any(keyword in domain for keyword in ['apple', 'icloud', 'itunes', 'appstore']):
            return AppType.APPLE
        
        # GitHub
        if any(keyword in domain for keyword in ['github', 'githubusercontent']):
            return AppType.GITHUB
        
        # Cloudflare
        if any(keyword in domain for keyword in ['cloudflare', 'cf']):
            return AppType.CLOUDFLARE
        
        # Gmail
        if any(keyword in domain for keyword in ['gmail']):
            return AppType.GMAIL
        
        # Slack
        if any(keyword in domain for keyword in ['slack']):
            return AppType.SLACK
        
        # Discord
        if any(keyword in domain for keyword in ['discord']):
            return AppType.DISCORD
        
        # Twitch
        if any(keyword in domain for keyword in ['twitch']):
            return AppType.TWITCH
        
        # Reddit
        if any(keyword in domain for keyword in ['reddit']):
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
