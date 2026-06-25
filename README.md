# Python Packet Analyzer - Deep Packet Inspection (DPI) Engine

A complete Python implementation of a Deep Packet Inspection engine that analyzes network traffic from PCAP files. This is a Python rewrite of the original C++ Packet Analyzer with all core features implemented.

## Features

✅ **PCAP Reader** - Reads and parses tcpdump PCAP files  
✅ **Packet Parser** - Parses Ethernet, IPv4, TCP/UDP headers  
✅ **Application Classification** - Identifies applications by SNI/Host headers  
✅ **TLS/HTTP Extraction** - Extracts SNI from TLS ClientHello and Host from HTTP  
✅ **DNS Extraction** - Parses DNS queries from UDP packets  
✅ **Connection Tracking** - Tracks network flows with statistics  
✅ **Rule Management** - Block/allow specific IPs, domains, and applications  
✅ **No External Dependencies** - Uses only Python standard library  
✅ **Thread-Safe** - All components use proper synchronization  

## Installation

### Requirements
- Python 3.6+
- No external dependencies required

### Setup
```bash
# Clone the repository
git clone https://github.com/devrajdev0606-alt/Deep-packet-inspection.git
cd Deep-packet-inspection

# No installation needed - just run!
python main.py <pcap_file>
```

## Quick Start

### Basic Usage

Analyze a PCAP file:
```bash
python main.py test_dpi.pcap
```

Analyze and save results to file:
```bash
python main.py test_dpi.pcap output.txt
```

### Python API Usage

```python
from packet_reader import PcapReader
from packet_parser import PacketParser
from sni_extractor import ApplicationExtractor
from types import AppTypeClassifier

# Read PCAP file
reader = PcapReader()
reader.open('test_dpi.pcap')

# Process packets
while True:
    raw_packet = reader.read_next_packet()
    if not raw_packet:
        break
    
    # Parse packet
    parsed = PacketParser.parse(raw_packet.data)
    if not parsed or not parsed.has_ip:
        continue
    
    # Extract application info
    app_info = ApplicationExtractor.extract_application_info(
        parsed.payload_data,
        parsed.src_port,
        parsed.dest_port
    )
    
    # Classify application
    app_type = AppTypeClassifier.classify(
        app_info.get('sni'),
        app_info.get('http_host')
    )
    
    print(f"Packet: {parsed.src_ip} -> {parsed.dest_ip}")
    print(f"  Application: {app_type.name}")
    print(f"  SNI: {app_info.get('sni')}")
    print(f"  HTTP Host: {app_info.get('http_host')}")

reader.close()
```

## File Structure

```
Deep-packet-inspection/
├── packet_reader.py          # PCAP file reading and parsing
├── packet_parser.py          # Network protocol parsing (Ethernet, IPv4, TCP, UDP)
├── sni_extractor.py          # TLS SNI, HTTP Host, and DNS extraction
├── types.py                  # Data structures and application classifier
├── connection_tracker.py     # Connection flow tracking (thread-safe)
├── rule_manager.py           # Rule management for blocking rules (thread-safe)
├── main.py                   # Main DPI engine
└── README.md                 # This file
```

## Module Documentation

### packet_reader.py
Handles reading PCAP format files with automatic byte-order detection.

**Key Classes:**
- `PcapReader` - Main PCAP file reader
- `RawPacket` - Raw packet data structure

**Key Methods:**
- `open(filename)` - Open PCAP file
- `read_next_packet()` - Read next packet
- `close()` - Close file

### packet_parser.py
Parses network packet headers at multiple layers.

**Key Classes:**
- `PacketParser` - Parser for network packets
- `ParsedPacket` - Parsed packet information
- `EtherType` - Ethernet frame types enum
- `Protocol` - IP protocol numbers enum

**Key Methods:**
- `parse(raw_data)` - Parse raw packet bytes
- `protocol_to_string(protocol)` - Convert protocol number to string
- `tcp_flags_to_string(flags)` - Convert TCP flags to string

### sni_extractor.py
Extracts application-level information from packet payloads.

**Key Classes:**
- `SNIExtractor` - Extract SNI from TLS ClientHello
- `HTTPExtractor` - Extract Host header from HTTP
- `DNSExtractor` - Extract DNS queries
- `ApplicationExtractor` - High-level application extraction

**Key Methods:**
- `SNIExtractor.extract_sni(payload)` - Get domain from TLS
- `HTTPExtractor.extract_host(payload)` - Get domain from HTTP
- `DNSExtractor.extract_query(payload)` - Get domain from DNS
- `ApplicationExtractor.extract_application_info()` - Extract all info

### types.py
Data structures and application classification logic.

**Key Classes:**
- `AppType` - Enum of application types
- `AppTypeClassifier` - Classify applications by domain
- `FiveTuple` - Network five-tuple for flow identification
- `Connection` - Connection flow information
- `ConnectionState` - Connection state enum

**Supported Applications:**
- Google, YouTube, Facebook, Instagram, WhatsApp
- Twitter/X, Netflix, Amazon/AWS, Microsoft/Azure
- Apple, GitHub, Slack, Discord, Twitch, Reddit
- And more...

### connection_tracker.py
Thread-safe connection tracking and flow management.

**Key Classes:**
- `ConnectionTracker` - Track network connections
- `TrackerStats` - Connection statistics

**Key Methods:**
- `track_packet()` - Track or update a connection
- `get_all_connections()` - Get all tracked connections
- `cleanup_stale()` - Remove old connections
- `get_stats()` - Get statistics

### rule_manager.py
Thread-safe blocking rule management.

**Key Classes:**
- `RuleManager` - Manage blocking rules

**Key Methods:**
- `block_ip(ip) / unblock_ip(ip)` - Block/unblock IP addresses
- `block_domain(domain) / unblock_domain(domain)` - Block/unblock domains (with wildcard support)
- `block_app(app) / unblock_app(app)` - Block/unblock applications
- `is_packet_blocked()` - Check if packet should be blocked

### main.py
Main DPI engine with complete analysis pipeline.

**Key Classes:**
- `SimpleDPIEngine` - Main engine for packet analysis

## Supported Protocols

**Layer 2 (Data Link):**
- Ethernet (with IPv4, IPv6, ARP, VLAN support)

**Layer 3 (Network):**
- IPv4 (with ICMP, TCP, UDP support)

**Layer 4 (Transport):**
- TCP with flag parsing
- UDP with port-based protocol detection

**Layer 7 (Application):**
- TLS/HTTPS with SNI extraction
- HTTP/1.1 with Host header extraction
- DNS with query domain extraction

## Performance Considerations

- **Memory Efficient**: Streams packets instead of loading entire file
- **Fast**: Minimal overhead, mostly binary parsing
- **Scalable**: Connection tracker has configurable timeout
- **Thread-Safe**: All shared data structures use proper locking

## Example Use Cases

### 1. Find All YouTube Traffic

```python
from types import AppType
from packet_reader import PcapReader
from packet_parser import PacketParser
from sni_extractor import ApplicationExtractor
from types import AppTypeClassifier

reader = PcapReader()
reader.open('capture.pcap')

youtube_flows = []
while True:
    raw = reader.read_next_packet()
    if not raw:
        break
    
    parsed = PacketParser.parse(raw.data)
    if not parsed or not parsed.has_ip:
        continue
    
    app_info = ApplicationExtractor.extract_application_info(
        parsed.payload_data, parsed.src_port, parsed.dest_port
    )
    
    app = AppTypeClassifier.classify(
        app_info.get('sni'),
        app_info.get('http_host')
    )
    
    if app == AppType.YOUTUBE:
        youtube_flows.append({
            'src': parsed.src_ip,
            'dst': parsed.dest_ip,
            'sni': app_info.get('sni')
        })

print(f"Found {len(youtube_flows)} YouTube flows")
reader.close()
```

### 2. Block All Social Media

```python
from rule_manager import RuleManager
from types import AppType

rules = RuleManager()

social_apps = [
    AppType.FACEBOOK,
    AppType.INSTAGRAM,
    AppType.TWITTER,
    AppType.REDDIT,
    AppType.DISCORD
]

for app in social_apps:
    rules.block_app(app)

# Later, check if packet is blocked
is_blocked = rules.is_packet_blocked(
    src_ip="192.168.1.1",
    dst_ip="1.2.3.4",
    app_type=AppType.FACEBOOK,
    domain="facebook.com"
)

print(f"Packet blocked: {is_blocked}")
```

### 3. Track All Connections

```python
from connection_tracker import ConnectionTracker
from types import FiveTuple, AppType

tracker = ConnectionTracker(timeout=300)

# Create a flow
tuple_obj = FiveTuple(
    src_ip=3232235777,  # 192.168.1.1
    dst_ip=134744072,   # 8.8.8.8
    src_port=12345,
    dst_port=443,
    protocol=6  # TCP
)

# Track it
conn = tracker.track_packet(
    tuple_obj,
    AppType.GOOGLE,
    sni="google.com",
    bytes_count=1500
)

# Get stats
stats = tracker.get_stats()
print(f"Active connections: {stats.active_connections}")
print(f"Classified: {stats.classified_connections}")
```

## Limitations

- IPv6 support is limited to header parsing
- QUIC SNI extraction is not fully supported (encrypted payload)
- DNS extraction limited to plain DNS over UDP (no DNS over HTTPS/TLS)
- PCAP-NG format not supported (standard PCAP only)
- Maximum packet size limited to 65535 bytes

## Architecture

```
Raw PCAP File
    ↓
PcapReader (binary reading)
    ↓
PacketParser (header parsing)
    ↓
ApplicationExtractor (SNI/Host/DNS)
    ↓
AppTypeClassifier (app identification)
    ↓
ConnectionTracker (flow tracking)
    ↓
RuleManager (blocking rules)
    ↓
Statistics & Results
```

## Contributing

Feel free to extend the code:
- Add support for more protocols
- Add more application classifiers
- Optimize performance
- Add IPv6 support
- Support additional packet formats

## License

Python port of the C++ Packet Analyzer. See original repository for licensing details.

## Original Project

This is a Python rewrite of: https://github.com/perryvegehan/Packet_analyzer

## Author

Python implementation created by devrajdev0606-alt
