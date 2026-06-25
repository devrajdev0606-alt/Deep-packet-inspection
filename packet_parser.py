"""
Network Packet Parser
Parses Ethernet, IPv4, TCP, and UDP headers
"""

import struct
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class EtherType(Enum):
    """Ethernet frame types"""
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806
    VLAN = 0x8100


class Protocol(Enum):
    """IP Protocol numbers"""
    ICMP = 1
    TCP = 6
    UDP = 17


@dataclass
class ParsedPacket:
    """Parsed packet information"""
    # Timestamps
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    
    # Ethernet layer
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    
    # IP layer
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    
    # TCP layer
    has_tcp: bool = False
    src_port: int = 0
    dest_port: int = 0
    seq_number: int = 0
    ack_number: int = 0
    tcp_flags: int = 0
    
    # UDP layer
    has_udp: bool = False
    
    # Payload
    payload_length: int = 0
    payload_data: bytes = field(default_factory=bytes)


class PacketParser:
    """Parser for network packets"""
    
    @staticmethod
    def mac_to_string(data: bytes) -> str:
        """Convert 6 bytes to MAC address string"""
        return ':'.join(f'{b:02x}' for b in data[:6])
    
    @staticmethod
    def ip_to_string(ip_int: int) -> str:
        """Convert 4-byte IP to dotted notation"""
        return f"{(ip_int >> 0) & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
    
    @staticmethod
    def parse(raw_data: bytes, raw_header=None) -> Optional[ParsedPacket]:
        """Parse a raw packet"""
        parsed = ParsedPacket()
        
        if len(raw_data) < 14:  # Minimum Ethernet header
            return None
        
        offset = 0
        
        # Parse Ethernet header
        if not PacketParser._parse_ethernet(raw_data, parsed, offset):
            return None
        offset = 14
        
        # Parse IP layer if it's IPv4
        if parsed.ether_type == EtherType.IPv4.value:
            if not PacketParser._parse_ipv4(raw_data, parsed, offset):
                return None
            
            # Parse transport layer based on protocol
            if parsed.protocol == Protocol.TCP.value:
                if not PacketParser._parse_tcp(raw_data, parsed, offset):
                    return None
            elif parsed.protocol == Protocol.UDP.value:
                if not PacketParser._parse_udp(raw_data, parsed, offset):
                    return None
        
        # Set payload information
        if offset < len(raw_data):
            parsed.payload_length = len(raw_data) - offset
            parsed.payload_data = raw_data[offset:]
        
        return parsed
    
    @staticmethod
    def _parse_ethernet(data: bytes, parsed: ParsedPacket, offset: int) -> bool:
        """Parse Ethernet header"""
        if len(data) < offset + 14:
            return False
        
        # Destination MAC (bytes 0-5)
        parsed.dest_mac = PacketParser.mac_to_string(data[offset:offset + 6])
        
        # Source MAC (bytes 6-11)
        parsed.src_mac = PacketParser.mac_to_string(data[offset + 6:offset + 12])
        
        # EtherType (bytes 12-13, big-endian)
        parsed.ether_type = struct.unpack('!H', data[offset + 12:offset + 14])[0]
        
        return True
    
    @staticmethod
    def _parse_ipv4(data: bytes, parsed: ParsedPacket, offset: int) -> bool:
        """Parse IPv4 header"""
        if len(data) < offset + 20:
            return False
        
        ip_data = data[offset:]
        
        # First byte: version (4 bits) + IHL (4 bits)
        version_ihl = ip_data[0]
        ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        
        if ip_version != 4:
            return False
        
        ip_header_len = ihl * 4
        if len(data) < offset + ip_header_len:
            return False
        
        parsed.has_ip = True
        parsed.ip_version = ip_version
        
        # TTL (byte 8)
        parsed.ttl = ip_data[8]
        
        # Protocol (byte 9)
        parsed.protocol = ip_data[9]
        
        # Source IP (bytes 12-15)
        src_ip_int = struct.unpack('!I', ip_data[12:16])[0]
        parsed.src_ip = PacketParser.ip_to_string(src_ip_int)
        
        # Destination IP (bytes 16-19)
        dest_ip_int = struct.unpack('!I', ip_data[16:20])[0]
        parsed.dest_ip = PacketParser.ip_to_string(dest_ip_int)
        
        # Update offset to transport layer
        offset_adj = ip_header_len
        
        return True
    
    @staticmethod
    def _parse_tcp(data: bytes, parsed: ParsedPacket, offset: int) -> bool:
        """Parse TCP header"""
        if len(data) < offset + 20:
            return False
        
        tcp_data = data[offset:]
        
        # Source port (bytes 0-1)
        parsed.src_port = struct.unpack('!H', tcp_data[0:2])[0]
        
        # Destination port (bytes 2-3)
        parsed.dest_port = struct.unpack('!H', tcp_data[2:4])[0]
        
        # Sequence number (bytes 4-7)
        parsed.seq_number = struct.unpack('!I', tcp_data[4:8])[0]
        
        # Acknowledgment number (bytes 8-11)
        parsed.ack_number = struct.unpack('!I', tcp_data[8:12])[0]
        
        # Data offset and flags (bytes 12-13)
        data_offset_flags = struct.unpack('!H', tcp_data[12:14])[0]
        parsed.tcp_flags = data_offset_flags & 0xFF
        
        parsed.has_tcp = True
        
        return True
    
    @staticmethod
    def _parse_udp(data: bytes, parsed: ParsedPacket, offset: int) -> bool:
        """Parse UDP header"""
        if len(data) < offset + 8:
            return False
        
        udp_data = data[offset:]
        
        # Source port (bytes 0-1)
        parsed.src_port = struct.unpack('!H', udp_data[0:2])[0]
        
        # Destination port (bytes 2-3)
        parsed.dest_port = struct.unpack('!H', udp_data[2:4])[0]
        
        parsed.has_udp = True
        
        return True
    
    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        """Convert protocol number to string"""
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }
        return protocols.get(protocol, f"Unknown({protocol})")
    
    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        """Convert TCP flags to string representation"""
        flag_names = []
        if flags & 0x01:
            flag_names.append("FIN")
        if flags & 0x02:
            flag_names.append("SYN")
        if flags & 0x04:
            flag_names.append("RST")
        if flags & 0x08:
            flag_names.append("PSH")
        if flags & 0x10:
            flag_names.append("ACK")
        if flags & 0x20:
            flag_names.append("URG")
        
        return ",".join(flag_names) if flag_names else "None"
    
    @staticmethod
    def ether_type_to_string(ether_type: int) -> str:
        """Convert EtherType to string"""
        types = {
            0x0800: "IPv4",
            0x86DD: "IPv6",
            0x0806: "ARP",
            0x8100: "VLAN"
        }
        return types.get(ether_type, f"Unknown(0x{ether_type:04x})")
