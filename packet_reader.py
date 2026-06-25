"""
PCAP File Reader
Handles reading PCAP (tcpdump) format files
"""

import struct
from dataclasses import dataclass
from typing import Optional

PCAP_MAGIC_NATIVE = 0xa1b2c3d4
PCAP_MAGIC_SWAPPED = 0xd4c3b2a1


@dataclass
class PcapGlobalHeader:
    """PCAP global header structure"""
    magic_number: int
    version_major: int
    version_minor: int
    timezone: int
    timestamp_accuracy: int
    snaplen: int
    network: int


@dataclass
class PcapPacketHeader:
    """PCAP packet header structure"""
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    """Raw packet data"""
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    """Reader for PCAP format files"""
    
    def __init__(self, filename: str = None):
        self.filename = filename
        self.file = None
        self.global_header = None
        self.needs_byte_swap = False
    
    def open(self, filename: str) -> bool:
        """Open and validate PCAP file"""
        try:
            self.close()
            self.file = open(filename, 'rb')
            
            # Read global header (24 bytes)
            header_data = self.file.read(24)
            if len(header_data) < 24:
                print(f"Error: Could not read PCAP global header from {filename}")
                return False
            
            # Parse magic number and determine byte order
            magic = struct.unpack('<I', header_data[0:4])[0]
            
            if magic == PCAP_MAGIC_NATIVE:
                self.needs_byte_swap = False
                fmt = '<IHHIIII'
            elif magic == PCAP_MAGIC_SWAPPED:
                self.needs_byte_swap = True
                fmt = '>IHHIIII'
            else:
                print(f"Error: Invalid PCAP magic number: 0x{magic:x}")
                self.close()
                return False
            
            # Parse header
            values = struct.unpack(fmt, header_data)
            self.global_header = PcapGlobalHeader(
                magic_number=values[0],
                version_major=values[1],
                version_minor=values[2],
                timezone=values[3],
                timestamp_accuracy=values[4],
                snaplen=values[5],
                network=values[6]
            )
            
            print(f"Opened PCAP file: {filename}")
            print(f"  Version: {self.global_header.version_major}.{self.global_header.version_minor}")
            print(f"  Snaplen: {self.global_header.snaplen} bytes")
            link_type = "Ethernet" if self.global_header.network == 1 else f"Type {self.global_header.network}"
            print(f"  Link type: {link_type}")
            
            return True
            
        except Exception as e:
            print(f"Error opening PCAP file: {e}")
            self.close()
            return False
    
    def close(self):
        """Close the file"""
        if self.file:
            self.file.close()
            self.file = None
        self.needs_byte_swap = False
    
    def read_next_packet(self) -> Optional[RawPacket]:
        """Read next packet from file"""
        if not self.file:
            return None
        
        try:
            # Read packet header (16 bytes)
            header_data = self.file.read(16)
            if len(header_data) < 16:
                return None  # End of file
            
            # Parse based on byte order
            fmt = '>IIII' if self.needs_byte_swap else '<IIII'
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, header_data)
            
            # Sanity check
            if incl_len > self.global_header.snaplen or incl_len > 65535:
                print(f"Error: Invalid packet length: {incl_len}")
                return None
            
            # Read packet data
            packet_data = self.file.read(incl_len)
            if len(packet_data) < incl_len:
                print(f"Error: Could not read complete packet data")
                return None
            
            header = PcapPacketHeader(
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                incl_len=incl_len,
                orig_len=orig_len
            )
            
            return RawPacket(header=header, data=packet_data)
            
        except Exception as e:
            print(f"Error reading packet: {e}")
            return None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
