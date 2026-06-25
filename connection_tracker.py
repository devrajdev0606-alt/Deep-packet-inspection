"""
Connection Tracker for managing network flows
Thread-safe connection tracking and classification
"""

import threading
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from types import Connection, FiveTuple, ConnectionState, AppType


@dataclass
class TrackerStats:
    """Statistics for connection tracker"""
    active_connections: int = 0
    total_connections_seen: int = 0
    classified_connections: int = 0
    blocked_connections: int = 0


class ConnectionTracker:
    """Tracks network connections"""
    
    def __init__(self, timeout: int = 300):
        self.connections: Dict[FiveTuple, Connection] = {}
        self.timeout = timeout
        self.total_seen = 0
        self.classified_count = 0
        self.blocked_count = 0
        self.lock = threading.RLock()
    
    def track_packet(self, tuple: FiveTuple, app_type: AppType, 
                    sni: str = "", http_host: str = "", 
                    bytes_count: int = 0) -> Connection:
        """Track or update a connection"""
        with self.lock:
            if tuple in self.connections:
                conn = self.connections[tuple]
                conn.packets_count += 1
                conn.bytes_count += bytes_count
                conn.last_seen = time.time()
            else:
                conn = Connection(
                    tuple=tuple,
                    app_type=app_type,
                    sni=sni,
                    http_host=http_host,
                    packets_count=1,
                    bytes_count=bytes_count,
                    first_seen=time.time(),
                    last_seen=time.time()
                )
                self.connections[tuple] = conn
                self.total_seen += 1
            
            # Update classification
            if app_type != AppType.UNKNOWN:
                if app_type != conn.app_type:
                    self.classified_count += 1
                conn.app_type = app_type
            
            # Update SNI/Host if not already set
            if sni and not conn.sni:
                conn.sni = sni
            if http_host and not conn.http_host:
                conn.http_host = http_host
            
            return conn
    
    def mark_blocked(self, tuple: FiveTuple) -> None:
        """Mark connection as blocked"""
        with self.lock:
            if tuple in self.connections:
                self.connections[tuple].blocked = True
                self.blocked_count += 1
    
    def get_connection(self, tuple: FiveTuple) -> Optional[Connection]:
        """Get connection by tuple"""
        with self.lock:
            return self.connections.get(tuple)
    
    def close_connection(self, tuple: FiveTuple) -> None:
        """Mark connection as closed"""
        with self.lock:
            if tuple in self.connections:
                self.connections[tuple].state = ConnectionState.CLOSED
    
    def cleanup_stale(self) -> int:
        """Remove stale connections"""
        current_time = time.time()
        removed = 0
        
        with self.lock:
            to_remove = []
            for tuple, conn in self.connections.items():
                age = current_time - conn.last_seen
                if age > self.timeout or conn.state == ConnectionState.CLOSED:
                    to_remove.append(tuple)
            
            for tuple in to_remove:
                del self.connections[tuple]
                removed += 1
        
        return removed
    
    def get_all_connections(self) -> List[Connection]:
        """Get all connections"""
        with self.lock:
            return list(self.connections.values())
    
    def get_active_count(self) -> int:
        """Get active connection count"""
        with self.lock:
            return len(self.connections)
    
    def get_stats(self) -> TrackerStats:
        """Get tracker statistics"""
        with self.lock:
            return TrackerStats(
                active_connections=len(self.connections),
                total_connections_seen=self.total_seen,
                classified_connections=self.classified_count,
                blocked_connections=self.blocked_count
            )
    
    def clear(self) -> None:
        """Clear all connections"""
        with self.lock:
            self.connections.clear()
    
    def for_each(self, callback) -> None:
        """Execute callback for each connection"""
        with self.lock:
            for conn in self.connections.values():
                callback(conn)
