"""
Main DPI Engine - Simple version for analyzing PCAP files
Reads packets, parses them, and classifies applications
"""

import sys
from datetime import datetime
from packet_reader import PcapReader
from packet_parser import PacketParser
from sni_extractor import ApplicationExtractor
from types import AppTypeClassifier, parse_ip_string, FiveTuple
from connection_tracker import ConnectionTracker
from rule_manager import RuleManager


class SimpleDPIEngine:
    """Simple DPI Engine for packet analysis"""
    
    def __init__(self):
        self.tracker = ConnectionTracker()
        self.rule_manager = RuleManager()
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'classified_packets': 0,
            'blocked_packets': 0
        }
    
    def process_pcap(self, pcap_file: str, output_file: str = None) -> None:
        """Process PCAP file"""
        reader = PcapReader()
        
        if not reader.open(pcap_file):
            print(f"Failed to open PCAP file: {pcap_file}")
            return
        
        print(f"\n[DPI Engine] Starting packet analysis...")
        packet_count = 0
        
        output_packets = []
        
        while True:
            raw_packet = reader.read_next_packet()
            if not raw_packet:
                break
            
            # Parse packet
            parsed = PacketParser.parse(raw_packet.data)
            if not parsed:
                continue
            
            # Update stats
            self.stats['total_packets'] += 1
            self.stats['total_bytes'] += len(raw_packet.data)
            
            if parsed.has_tcp:
                self.stats['tcp_packets'] += 1
            elif parsed.has_udp:
                self.stats['udp_packets'] += 1
            
            # Skip non-IP packets
            if not parsed.has_ip:
                continue
            
            # Extract application info if there's payload
            app_info = {}
            if parsed.payload_length > 0:
                app_info = ApplicationExtractor.extract_application_info(
                    parsed.payload_data, 
                    parsed.src_port, 
                    parsed.dest_port
                )
            
            # Classify application
            sni = app_info.get('sni', '')
            http_host = app_info.get('http_host', '')
            app_type = AppTypeClassifier.classify(sni, http_host)
            
            if app_type.value != 0:  # Not UNKNOWN
                self.stats['classified_packets'] += 1
            
            # Create five-tuple
            tuple_obj = FiveTuple(
                src_ip=parse_ip_string(parsed.src_ip),
                dst_ip=parse_ip_string(parsed.dest_ip),
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol
            )
            
            # Track connection
            self.tracker.track_packet(tuple_obj, app_type, sni, http_host, len(raw_packet.data))
            
            # Check if should block
            is_blocked = self.rule_manager.is_packet_blocked(
                parsed.src_ip, 
                parsed.dest_ip, 
                app_type, 
                sni or http_host
            )
            
            if is_blocked:
                self.stats['blocked_packets'] += 1
            
            output_packets.append({
                'packet_num': packet_count,
                'timestamp': parsed.timestamp_sec,
                'src_ip': parsed.src_ip,
                'dst_ip': parsed.dest_ip,
                'src_port': parsed.src_port,
                'dest_port': parsed.dest_port,
                'protocol': PacketParser.protocol_to_string(parsed.protocol),
                'app_type': app_type.name,
                'sni': sni,
                'http_host': http_host,
                'payload_len': parsed.payload_length,
                'blocked': is_blocked
            })
            
            packet_count += 1
        
        reader.close()
        
        print(f"[DPI Engine] Processed {packet_count} packets\n")
        
        # Print summary
        self.print_summary()
        
        # Print detailed packet info if output file specified
        if output_file:
            self.save_results(output_packets, output_file)
        else:
            # Print first 20 packets
            print("\n[Packets Analyzed] (first 20 shown):")
            print("-" * 120)
            print(f"{'#':<5} {'Time':<12} {'Src IP':<15} {'Dst IP':<15} {'Src Port':<6} {'Dst Port':<6} {'App':<15} {'SNI/Host':<20} {'Blocked':<8}")
            print("-" * 120)
            
            for pkt in output_packets[:20]:
                timestamp = datetime.fromtimestamp(pkt['timestamp']).strftime('%H:%M:%S')
                sni_host = pkt['sni'] or pkt['http_host'] or '-'
                blocked_str = "YES" if pkt['blocked'] else "NO"
                
                print(f"{pkt['packet_num']:<5} {timestamp:<12} {pkt['src_ip']:<15} {pkt['dst_ip']:<15} "
                      f"{pkt['src_port']:<6} {pkt['dest_port']:<6} {pkt['app_type']:<15} "
                      f"{sni_host:<20} {blocked_str:<8}")
    
    def print_summary(self) -> None:
        """Print statistics summary"""
        print("=" * 60)
        print("[DPI Engine Statistics]")
        print("=" * 60)
        print(f"Total Packets:        {self.stats['total_packets']}")
        print(f"Total Bytes:          {self.stats['total_bytes']} bytes")
        print(f"TCP Packets:          {self.stats['tcp_packets']}")
        print(f"UDP Packets:          {self.stats['udp_packets']}")
        print(f"Classified Packets:   {self.stats['classified_packets']}")
        print(f"Blocked Packets:      {self.stats['blocked_packets']}")
        print("=" * 60)
        
        # Connection statistics
        connections = self.tracker.get_all_connections()
        print(f"\n[Connection Statistics]")
        print(f"Active Connections:   {self.tracker.get_active_count()}")
        
        # App distribution
        app_dist = {}
        for conn in connections:
            app_name = conn.app_type.name
            app_dist[app_name] = app_dist.get(app_name, 0) + 1
        
        if app_dist:
            print(f"\n[Application Distribution]")
            for app, count in sorted(app_dist.items(), key=lambda x: x[1], reverse=True):
                print(f"  {app}: {count} connections")
        
        # Top domains
        domains = {}
        for conn in connections:
            domain = conn.sni or conn.http_host
            if domain:
                domains[domain] = domains.get(domain, 0) + 1
        
        if domains:
            print(f"\n[Top Domains]")
            for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {domain}: {count} connections")
    
    def save_results(self, packets: list, output_file: str) -> None:
        """Save results to file"""
        try:
            with open(output_file, 'w') as f:
                f.write("Packet Analysis Results\n")
                f.write("=" * 150 + "\n")
                f.write(f"{'#':<5} {'Time':<12} {'Src IP':<15} {'Dst IP':<15} {'Src Port':<6} "
                       f"{'Dst Port':<6} {'Protocol':<6} {'App':<15} {'SNI/Host':<25} {'Payload':<8} {'Blocked':<8}\n")
                f.write("=" * 150 + "\n")
                
                for pkt in packets:
                    timestamp = datetime.fromtimestamp(pkt['timestamp']).strftime('%H:%M:%S')
                    sni_host = pkt['sni'] or pkt['http_host'] or '-'
                    blocked_str = "YES" if pkt['blocked'] else "NO"
                    
                    f.write(f"{pkt['packet_num']:<5} {timestamp:<12} {pkt['src_ip']:<15} {pkt['dst_ip']:<15} "
                           f"{pkt['src_port']:<6} {pkt['dest_port']:<6} {pkt['protocol']:<6} {pkt['app_type']:<15} "
                           f"{sni_host:<25} {pkt['payload_len']:<8} {blocked_str:<8}\n")
            
            print(f"\n[Results saved to {output_file}]")
        
        except Exception as e:
            print(f"Error saving results: {e}")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python main.py <pcap_file> [output_file]")
        print("Example: python main.py test_dpi.pcap output.txt")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    engine = SimpleDPIEngine()
    engine.process_pcap(pcap_file, output_file)


if __name__ == "__main__":
    main()
