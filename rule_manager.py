"""
Rule Manager for blocking rules
Thread-safe management of blocking rules for IPs, domains, and applications
"""

import threading
from typing import Set, List
from packet_types import AppType


class RuleManager:
    """Manages blocking rules for IPs, domains, and applications"""
    
    def __init__(self):
        self.blocked_ips: Set[int] = set()
        self.blocked_domains: Set[str] = set()
        self.domain_patterns: List[str] = []
        self.blocked_apps: Set[AppType] = set()
        
        # Thread synchronization
        self.ip_lock = threading.RLock()
        self.domain_lock = threading.RLock()
        self.app_lock = threading.RLock()
    
    def block_ip(self, ip: str) -> None:
        """Block an IP address"""
        ip_int = self._parse_ip(ip)
        if ip_int == 0:
            return
        
        with self.ip_lock:
            self.blocked_ips.add(ip_int)
            print(f"[RuleManager] Blocked IP: {ip}")
    
    def unblock_ip(self, ip: str) -> None:
        """Unblock an IP address"""
        ip_int = self._parse_ip(ip)
        if ip_int == 0:
            return
        
        with self.ip_lock:
            self.blocked_ips.discard(ip_int)
            print(f"[RuleManager] Unblocked IP: {ip}")
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        ip_int = self._parse_ip(ip)
        if ip_int == 0:
            return False
        
        with self.ip_lock:
            return ip_int in self.blocked_ips
    
    def block_domain(self, domain: str) -> None:
        """Block a domain"""
        with self.domain_lock:
            if '*' in domain:
                self.domain_patterns.append(domain)
            else:
                self.blocked_domains.add(domain.lower())
            
            print(f"[RuleManager] Blocked domain: {domain}")
    
    def unblock_domain(self, domain: str) -> None:
        """Unblock a domain"""
        with self.domain_lock:
            if '*' in domain:
                if domain in self.domain_patterns:
                    self.domain_patterns.remove(domain)
            else:
                self.blocked_domains.discard(domain.lower())
            
            print(f"[RuleManager] Unblocked domain: {domain}")
    
    def is_domain_blocked(self, domain: str) -> bool:
        """Check if domain is blocked"""
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        with self.domain_lock:
            # Check exact match
            if domain_lower in self.blocked_domains:
                return True
            
            # Check wildcard patterns
            for pattern in self.domain_patterns:
                if self._match_pattern(domain_lower, pattern):
                    return True
        
        return False
    
    def block_app(self, app: AppType) -> None:
        """Block an application type"""
        with self.app_lock:
            self.blocked_apps.add(app)
            print(f"[RuleManager] Blocked app: {app.name}")
    
    def unblock_app(self, app: AppType) -> None:
        """Unblock an application type"""
        with self.app_lock:
            self.blocked_apps.discard(app)
            print(f"[RuleManager] Unblocked app: {app.name}")
    
    def is_app_blocked(self, app: AppType) -> bool:
        """Check if application is blocked"""
        with self.app_lock:
            return app in self.blocked_apps
    
    def is_packet_blocked(self, src_ip: str, dst_ip: str, 
                         app_type: AppType, domain: str = "") -> bool:
        """Check if packet should be blocked"""
        if self.is_ip_blocked(src_ip) or self.is_ip_blocked(dst_ip):
            return True
        
        if self.is_app_blocked(app_type):
            return True
        
        if domain and self.is_domain_blocked(domain):
            return True
        
        return False
    
    @staticmethod
    def _parse_ip(ip_str: str) -> int:
        """Parse IP string to integer"""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return 0
            
            return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        except (ValueError, AttributeError):
            return 0
    
    @staticmethod
    def _match_pattern(domain: str, pattern: str) -> bool:
        """Match domain against wildcard pattern"""
        parts = pattern.split('*')
        
        if len(parts) == 1:
            return domain == pattern
        
        if not domain.startswith(parts[0]):
            return False
        
        if not domain.endswith(parts[-1]):
            return False
        
        pos = len(parts[0])
        for part in parts[1:-1]:
            if not part:
                continue
            
            idx = domain.find(part, pos)
            if idx == -1:
                return False
            pos = idx + len(part)
        
        return True
