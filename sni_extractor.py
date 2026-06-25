"""
SNI and Host Header Extractor
Extracts Server Name Indication (SNI) from TLS ClientHello
Extracts Host header from HTTP requests
Extracts DNS queries
"""

from typing import Optional
from enum import Enum


class TLSContentType(Enum):
    """TLS Content Types"""
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24


class TLSHandshakeType(Enum):
    """TLS Handshake Types"""
    CLIENT_HELLO = 1
    SERVER_HELLO = 2


class SNIExtractor:
    """Extract SNI from TLS ClientHello"""
    
    @staticmethod
    def is_tls_handshake(payload: bytes) -> bool:
        """Check if payload contains TLS handshake"""
        if len(payload) < 6:
            return False
        
        # TLS record header: Content Type (1) + Version (2) + Length (2)
        content_type = payload[0]
        
        # Should be Handshake (22)
        if content_type != TLSContentType.HANDSHAKE.value:
            return False
        
        # TLS version check (optional, 0x03 0x01 = TLS 1.0, etc.)
        tls_version = (payload[1] << 8) | payload[2]
        if tls_version < 0x0301 or tls_version > 0x0304:
            return False
        
        return True
    
    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        """Check if payload contains TLS ClientHello"""
        if not SNIExtractor.is_tls_handshake(payload):
            return False
        
        if len(payload) <= 5:
            return False
        
        # Handshake type should be ClientHello (1)
        if payload[5] == TLSHandshakeType.CLIENT_HELLO.value:
            return True
        
        return False
    
    @staticmethod
    def extract_sni(payload: bytes) -> Optional[str]:
        """Extract SNI from TLS ClientHello with improved robustness"""
        if not SNIExtractor.is_tls_client_hello(payload):
            return None
        
        try:
            # Skip TLS record header (5 bytes)
            offset = 5
            
            # Skip Handshake header (4 bytes: type + length)
            offset += 4
            
            # Skip ClientHello fixed fields
            if len(payload) < offset + 32:
                return None
            
            # Skip Protocol Version (2) + Random (32)
            offset += 34
            
            # Skip Session ID
            if offset >= len(payload):
                return None
            
            session_id_len = payload[offset]
            if session_id_len > 32:  # Session ID should be <= 32 bytes
                return None
            offset += 1 + session_id_len
            
            # Skip Cipher Suites
            if offset + 2 > len(payload):
                return None
            
            cipher_suites_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2 + cipher_suites_len
            
            # Skip Compression Methods
            if offset >= len(payload):
                return None
            
            compression_methods_len = payload[offset]
            offset += 1 + compression_methods_len
            
            # Now we're at Extensions
            if offset + 2 > len(payload):
                return None
            
            extensions_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            
            # Parse extensions with bounds checking
            extensions_end = min(offset + extensions_len, len(payload))
            while offset + 4 <= extensions_end:
                ext_type = (payload[offset] << 8) | payload[offset + 1]
                ext_len = (payload[offset + 2] << 8) | payload[offset + 3]
                offset += 4
                
                # Validate extension length
                if offset + ext_len > len(payload):
                    break
                
                # Extension type 0 = server_name
                if ext_type == 0:
                    ext_data = payload[offset:offset + ext_len]
                    
                    # Parse server_name extension
                    if len(ext_data) < 5:
                        break
                    
                    # Skip server_name_list_len (2 bytes)
                    sni_offset = 2
                    
                    if sni_offset + 3 > len(ext_data):
                        break
                    
                    # Skip name_type (1 byte) - should be 0 (host_name)
                    if ext_data[sni_offset] != 0:
                        break
                    sni_offset += 1
                    
                    # Get name_len
                    name_len = (ext_data[sni_offset] << 8) | ext_data[sni_offset + 1]
                    sni_offset += 2
                    
                    if sni_offset + name_len > len(ext_data):
                        break
                    
                    if name_len > 0 and name_len < 256:  # Reasonable domain name length
                        sni = ext_data[sni_offset:sni_offset + name_len].decode('ascii', errors='ignore')
                        if sni and len(sni) > 0:
                            return sni
                
                offset += ext_len
            
            return None
            
        except Exception:
            return None


class HTTPExtractor:
    """Extract Host header from HTTP requests"""
    
    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        """Check if payload looks like HTTP request"""
        if len(payload) < 10:
            return False
        
        # Check for common HTTP methods
        http_methods = [b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', 
                       b'OPTIONS ', b'PATCH ', b'TRACE ', b'CONNECT ']
        
        for method in http_methods:
            if payload.startswith(method):
                return True
        
        return False
    
    @staticmethod
    def extract_host(payload: bytes) -> Optional[str]:
        """Extract Host header from HTTP request"""
        if not HTTPExtractor.is_http_request(payload):
            return None
        
        try:
            # Decode payload as ASCII, ignoring errors
            text = payload.decode('ascii', errors='ignore')
            
            # Search for Host header (case-insensitive)
            lines = text.split('\n')
            for line in lines:
                if line.lower().startswith('host:'):
                    # Extract host value
                    host = line[5:].strip()
                    # Remove port if present
                    if ':' in host:
                        host = host.split(':')[0]
                    return host
            
            return None
            
        except Exception:
            return None


class DNSExtractor:
    """Extract DNS queries"""
    
    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        """Check if payload is DNS query"""
        if len(payload) < 12:
            return False
        
        # Check QR bit (byte 2, bit 7) - should be 0 for query
        flags = payload[2]
        if flags & 0x80:
            return False  # This is a response
        
        # Check QDCOUNT (bytes 4-5) - should be > 0
        qdcount = (payload[4] << 8) | payload[5]
        if qdcount == 0:
            return False
        
        return True
    
    @staticmethod
    def is_dns_response(payload: bytes) -> bool:
        """Check if payload is DNS response"""
        if len(payload) < 12:
            return False
        
        # Check QR bit (byte 2, bit 7) - should be 1 for response
        flags = payload[2]
        if not (flags & 0x80):
            return False  # This is a query
        
        # Check ANCOUNT (bytes 6-7) - should be > 0 for valid response
        ancount = (payload[6] << 8) | payload[7]
        if ancount == 0:
            return False
        
        return True
    
    @staticmethod
    def extract_query(payload: bytes) -> Optional[str]:
        """Extract DNS query domain"""
        if not DNSExtractor.is_dns_query(payload) and not DNSExtractor.is_dns_response(payload):
            return None
        
        try:
            # DNS query starts at byte 12
            offset = 12
            domain = []
            
            while offset < len(payload):
                label_len = payload[offset]
                
                if label_len == 0:
                    # End of domain name
                    break
                
                if label_len > 63:
                    # Compression pointer or invalid
                    break
                
                offset += 1
                if offset + label_len > len(payload):
                    break
                
                label = payload[offset:offset + label_len].decode('ascii', errors='ignore')
                domain.append(label)
                offset += label_len
            
            return '.'.join(domain) if domain else None
            
        except Exception:
            return None


class ApplicationExtractor:
    """Extract application information from packets"""
    
    @staticmethod
    def extract_application_info(payload: bytes, src_port: int, dst_port: int) -> dict:
        """Extract various application information"""
        info = {
            'sni': None,
            'http_host': None,
            'dns_query': None,
            'protocol': 'unknown'
        }
        
        if not payload:
            return info
        
        # Check for DNS (port 53)
        if dst_port == 53 or src_port == 53:
            if DNSExtractor.is_dns_query(payload) or DNSExtractor.is_dns_response(payload):
                info['dns_query'] = DNSExtractor.extract_query(payload)
                info['protocol'] = 'DNS'
                return info
        
        # Check for TLS/HTTPS - Try to extract SNI
        if SNIExtractor.is_tls_handshake(payload):
            sni = SNIExtractor.extract_sni(payload)
            if sni:
                info['sni'] = sni
                info['protocol'] = 'TLS/HTTPS'
                return info
            # Even if SNI extraction fails, it's still TLS
            info['protocol'] = 'TLS/HTTPS'
            return info
        
        # Check for HTTP
        if HTTPExtractor.is_http_request(payload):
            info['http_host'] = HTTPExtractor.extract_host(payload)
            info['protocol'] = 'HTTP'
            return info
        
        return info
