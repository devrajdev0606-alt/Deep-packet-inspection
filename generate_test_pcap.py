#!/usr/bin/env python3
"""
Generate a test PCAP file with sample DNS and HTTP packets
for testing the DPI engine
"""

import struct
import time
import random

# PCAP file format constants
PCAP_MAGIC_NUMBER = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_NETWORK = 1  # Ethernet


def write_pcap_global_header(f):
    """Write PCAP global header"""
    header = struct.pack('<IHHIIII',
        PCAP_MAGIC_NUMBER,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,  # timezone
        0,  # timestamp_accuracy
        PCAP_SNAPLEN,
        PCAP_NETWORK
    )
    f.write(header)


def write_pcap_packet(f, packet_data, timestamp=None):
    """Write a packet to PCAP file"""
    if timestamp is None:
        timestamp = time.time()
    
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    
    header = struct.pack('<IIII',
        ts_sec,
        ts_usec,
        len(packet_data),
        len(packet_data)
    )
    f.write(header)
    f.write(packet_data)


def create_ethernet_frame(src_mac, dst_mac, eth_type, payload):
    """Create Ethernet frame"""
    frame = src_mac + dst_mac + struct.pack('!H', eth_type) + payload
    return frame


def create_ipv4_header(src_ip, dst_ip, protocol, payload_len):
    """Create IPv4 header"""
    # IP version (4) + IHL (5)
    version_ihl = 0x45
    # DSCP + ECN (0)
    dscp_ecn = 0
    # Total length
    total_length = 20 + payload_len
    # Identification
    identification = random.randint(0, 65535)
    # Flags (0) + Fragment offset (0)
    flags_frag = 0
    # TTL
    ttl = 64
    # Checksum (0 for now)
    checksum = 0
    
    # Parse IPs
    src_parts = [int(x) for x in src_ip.split('.')]
    dst_parts = [int(x) for x in dst_ip.split('.')]
    src_ip_int = (src_parts[0] << 24) | (src_parts[1] << 16) | (src_parts[2] << 8) | src_parts[3]
    dst_ip_int = (dst_parts[0] << 24) | (dst_parts[1] << 16) | (dst_parts[2] << 8) | dst_parts[3]
    
    header = struct.pack('!BBHHHBBH4s4s',
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        checksum,
        struct.pack('!I', src_ip_int),
        struct.pack('!I', dst_ip_int)
    )
    
    return header


def create_udp_header(src_port, dst_port, payload):
    """Create UDP header"""
    length = 8 + len(payload)
    checksum = 0
    
    header = struct.pack('!HHHH',
        src_port,
        dst_port,
        length,
        checksum
    )
    
    return header + payload


def create_dns_query(domain):
    """Create a simple DNS query packet"""
    # DNS header
    transaction_id = random.randint(0, 65535)
    flags = 0x0000  # Query
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0
    
    dns_header = struct.pack('!HHHHHH',
        transaction_id,
        flags,
        questions,
        answer_rrs,
        authority_rrs,
        additional_rrs
    )
    
    # Convert domain to DNS format
    # example.com -> \x07example\x03com\x00
    dns_domain = b''
    for part in domain.split('.'):
        dns_domain += struct.pack('B', len(part)) + part.encode()
    dns_domain += b'\x00'
    
    # Query type A (1) and class IN (1)
    dns_query = dns_domain + struct.pack('!HH', 1, 1)
    
    return dns_header + dns_query


def create_http_request(host, path='/'):
    """Create a simple HTTP request"""
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    return request.encode()


def create_test_pcap(filename):
    """Generate a test PCAP file"""
    print(f"Generating test PCAP file: {filename}")
    
    src_mac = bytes([0x08, 0x00, 0x27, 0x00, 0x00, 0x00])
    dst_mac = bytes([0x08, 0x00, 0x27, 0x00, 0x00, 0x01])
    
    with open(filename, 'wb') as f:
        # Write global header
        write_pcap_global_header(f)
        
        timestamp = time.time()
        
        # Generate DNS queries
        dns_domains = ['google.com', 'youtube.com', 'facebook.com', 'github.com', 'example.com']
        print(f"  Adding {len(dns_domains)} DNS queries...")
        
        for domain in dns_domains:
            dns_payload = create_dns_query(domain)
            udp_packet = create_udp_header(54321, 53, dns_payload)
            ipv4_header = create_ipv4_header('192.168.1.100', '8.8.8.8', 17, len(udp_packet))
            eth_frame = create_ethernet_frame(src_mac, dst_mac, 0x0800, ipv4_header + udp_packet)
            
            write_pcap_packet(f, eth_frame, timestamp)
            timestamp += 0.1
        
        # Generate HTTP requests
        http_domains = ['google.com', 'example.com', 'github.com']
        print(f"  Adding {len(http_domains)} HTTP requests...")
        
        for host in http_domains:
            http_payload = create_http_request(host)
            udp_packet = create_udp_header(12345, 80, http_payload)
            ipv4_header = create_ipv4_header('192.168.1.100', '93.184.216.34', 17, len(udp_packet))
            eth_frame = create_ethernet_frame(src_mac, dst_mac, 0x0800, ipv4_header + udp_packet)
            
            write_pcap_packet(f, eth_frame, timestamp)
            timestamp += 0.1
        
        # Add some random traffic
        print(f"  Adding random traffic...")
        for i in range(10):
            src_port = random.randint(10000, 60000)
            dst_port = random.choice([80, 443, 53, 22])
            payload = bytes([random.randint(0, 255) for _ in range(random.randint(10, 100))])
            
            if dst_port == 53:
                # DNS
                udp_packet = create_udp_header(src_port, dst_port, payload[:50])
                ipv4_header = create_ipv4_header('172.20.10.1', '172.20.10.6', 17, len(udp_packet))
            else:
                # Generic
                udp_packet = create_udp_header(src_port, dst_port, payload)
                ipv4_header = create_ipv4_header('172.20.10.1', '172.20.10.1', 17, len(udp_packet))
            
            eth_frame = create_ethernet_frame(src_mac, dst_mac, 0x0800, ipv4_header + udp_packet)
            write_pcap_packet(f, eth_frame, timestamp)
            timestamp += 0.05
    
    print(f"✅ Test PCAP generated: {filename}")
    print(f"   Ready to analyze with: python main.py {filename}\n")


if __name__ == '__main__':
    create_test_pcap('test_dpi.pcap')
