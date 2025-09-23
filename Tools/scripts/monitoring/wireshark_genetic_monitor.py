"""
Wireshark Network Monitoring with Genetic Algorithm Optimization
Combines Wireshark packet capture with genetic algorithms for intelligent traffic analysis
"""

import subprocess
import json
import os
import sys
import time
import random
import numpy as np
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import datetime
import sqlite3
import hashlib
import re
from enum import Enum
import threading
import queue
import signal

# Configure SQLite3 for Python 3.12+ compatibility
sqlite3.register_adapter(datetime.datetime, lambda dt: dt.isoformat())
sqlite3.register_adapter(datetime.date, lambda d: d.isoformat())


class PacketType(Enum):
    """Types of network packets"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    ARP = "arp"
    DHCP = "dhcp"
    OTHER = "other"


class ThreatLevel(Enum):
    """Threat levels for network traffic"""
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class NetworkPacket:
    """Represents a captured network packet"""
    timestamp: datetime.datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    packet_type: PacketType
    size: int
    payload_hash: str
    flags: List[str]
    threat_level: ThreatLevel
    metadata: Dict[str, Any]


@dataclass
class FilterRule:
    """Represents a Wireshark capture filter rule"""
    rule_id: str
    expression: str
    priority: int
    fitness_score: float
    matches: int
    false_positives: int
    generation: int
    parent_ids: List[str]
    metadata: Dict[str, Any]


class GeneticFilterOptimizer:
    """Genetic algorithm for optimizing Wireshark filter rules"""
    
    def __init__(self, 
                 population_size: int = 50,
                 mutation_rate: float = 0.1,
                 crossover_rate: float = 0.7,
                 elitism_rate: float = 0.2):
        """
        Initialize the genetic optimizer
        
        Args:
            population_size: Number of filter rules in each generation
            mutation_rate: Probability of mutation
            crossover_rate: Probability of crossover
            elitism_rate: Percentage of best individuals to keep
        """
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.elitism_rate = elitism_rate
        self.generation = 0
        self.population = []
        self.best_filters = []
        
        # Filter components for genetic operations
        self.protocols = ["tcp", "udp", "icmp", "arp", "http", "https", "dns", "ssh"]
        self.operators = ["==", "!=", "&&", "||", "contains", "matches"]
        self.fields = ["ip.src", "ip.dst", "tcp.port", "udp.port", "ip.len", 
                      "tcp.flags", "http.request", "dns.qry.name"]
        
    def initialize_population(self) -> List[FilterRule]:
        """Create initial population of filter rules"""
        population = []
        
        # Add some known good filters
        base_filters = [
            "tcp.flags.syn == 1 && tcp.flags.ack == 0",  # SYN flood detection
            "icmp && ip.len > 1000",  # Large ICMP packets (potential DoS)
            "tcp.port == 445 || tcp.port == 139",  # SMB traffic
            "dns && udp.length > 512",  # Large DNS responses
            "tcp.analysis.retransmission",  # Retransmissions
            "http.request.method == POST",  # HTTP POST requests
            "tcp.flags.fin == 1 && tcp.flags.push == 1",  # FIN+PSH flags
            "arp.duplicate-address-detected",  # ARP spoofing
        ]
        
        for i, filter_expr in enumerate(base_filters):
            rule = FilterRule(
                rule_id=f"rule_{self.generation}_{i}",
                expression=filter_expr,
                priority=random.randint(1, 10),
                fitness_score=0.5,
                matches=0,
                false_positives=0,
                generation=self.generation,
                parent_ids=[],
                metadata={"type": "base"}
            )
            population.append(rule)
        
        # Generate random filters to fill population
        while len(population) < self.population_size:
            filter_expr = self._generate_random_filter()
            rule = FilterRule(
                rule_id=f"rule_{self.generation}_{len(population)}",
                expression=filter_expr,
                priority=random.randint(1, 10),
                fitness_score=0.0,
                matches=0,
                false_positives=0,
                generation=self.generation,
                parent_ids=[],
                metadata={"type": "random"}
            )
            population.append(rule)
        
        self.population = population
        return population
    
    def _generate_random_filter(self) -> str:
        """Generate a random filter expression"""
        num_conditions = random.randint(1, 3)
        conditions = []
        
        for _ in range(num_conditions):
            field = random.choice(self.fields)
            
            if field in ["ip.src", "ip.dst"]:
                # Generate IP-based condition
                ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.0/24"
                condition = f"{field} == {ip}"
            elif field in ["tcp.port", "udp.port"]:
                # Generate port-based condition
                port = random.choice([22, 23, 25, 80, 443, 445, 3306, 3389, 8080])
                condition = f"{field} == {port}"
            elif field == "ip.len":
                # Generate length-based condition
                length = random.choice([64, 128, 256, 512, 1024, 1500])
                operator = random.choice([">", "<", "=="])
                condition = f"{field} {operator} {length}"
            elif field == "tcp.flags":
                # Generate TCP flags condition
                flag = random.choice(["syn", "ack", "fin", "rst", "push"])
                condition = f"tcp.flags.{flag} == 1"
            else:
                # Generate protocol-based condition
                protocol = random.choice(self.protocols)
                condition = protocol
            
            conditions.append(condition)
        
        # Combine conditions
        if len(conditions) > 1:
            operator = random.choice([" && ", " || "])
            return operator.join(conditions)
        return conditions[0]
    
    def evaluate_fitness(self, rule: FilterRule, packet_data: List[NetworkPacket]) -> float:
        """
        Evaluate fitness of a filter rule based on packet captures
        
        Args:
            rule: Filter rule to evaluate
            packet_data: List of captured packets
        
        Returns:
            Fitness score (0.0 to 1.0)
        """
        if not packet_data:
            return 0.0
        
        # Simulate filter matching (in real implementation, use tshark)
        matches = 0
        false_positives = 0
        true_positives = 0
        
        for packet in packet_data:
            # Simplified matching logic (replace with actual Wireshark filter evaluation)
            if self._matches_filter(rule.expression, packet):
                matches += 1
                if packet.threat_level.value >= ThreatLevel.MEDIUM.value:
                    true_positives += 1
                else:
                    false_positives += 1
        
        # Calculate fitness components
        detection_rate = true_positives / max(1, sum(1 for p in packet_data 
                                                     if p.threat_level.value >= ThreatLevel.MEDIUM.value))
        false_positive_rate = false_positives / max(1, len(packet_data))
        
        # Fitness function: maximize detection, minimize false positives
        fitness = (detection_rate * 0.7) + ((1 - false_positive_rate) * 0.3)
        
        # Update rule statistics
        rule.matches = matches
        rule.false_positives = false_positives
        rule.fitness_score = fitness
        
        return fitness
    
    def _matches_filter(self, filter_expr: str, packet: NetworkPacket) -> bool:
        """Simplified filter matching (replace with actual tshark evaluation)"""
        # This is a simplified simulation - in production, use tshark
        if "tcp" in filter_expr.lower() and packet.protocol == "TCP":
            return True
        if "syn" in filter_expr and "SYN" in packet.flags:
            return True
        if "port == 445" in filter_expr and (packet.dest_port == 445 or packet.source_port == 445):
            return True
        if "icmp" in filter_expr.lower() and packet.protocol == "ICMP":
            return True
        return random.random() < 0.1  # Random match for simulation
    
    def crossover(self, parent1: FilterRule, parent2: FilterRule) -> FilterRule:
        """Perform crossover between two parent rules"""
        if random.random() > self.crossover_rate:
            return parent1 if random.random() < 0.5 else parent2
        
        # Parse filter expressions
        parts1 = re.split(r'(\s+&&\s+|\s+\|\|\s+)', parent1.expression)
        parts2 = re.split(r'(\s+&&\s+|\s+\|\|\s+)', parent2.expression)
        
        # Combine parts from both parents
        new_parts = []
        for i in range(max(len(parts1), len(parts2))):
            if i < len(parts1) and i < len(parts2):
                new_parts.append(parts1[i] if random.random() < 0.5 else parts2[i])
            elif i < len(parts1):
                new_parts.append(parts1[i])
            elif i < len(parts2):
                new_parts.append(parts2[i])
        
        new_expression = "".join(new_parts)
        
        return FilterRule(
            rule_id=f"rule_{self.generation}_{random.randint(1000, 9999)}",
            expression=new_expression,
            priority=(parent1.priority + parent2.priority) // 2,
            fitness_score=0.0,
            matches=0,
            false_positives=0,
            generation=self.generation,
            parent_ids=[parent1.rule_id, parent2.rule_id],
            metadata={"type": "crossover"}
        )
    
    def mutate(self, rule: FilterRule) -> FilterRule:
        """Apply mutation to a filter rule"""
        if random.random() > self.mutation_rate:
            return rule
        
        mutation_type = random.choice(["add", "remove", "modify"])
        expression = rule.expression
        
        if mutation_type == "add":
            # Add a new condition
            new_condition = self._generate_random_filter()
            operator = random.choice([" && ", " || "])
            expression = f"({expression}){operator}{new_condition}"
        
        elif mutation_type == "remove":
            # Remove a condition
            parts = re.split(r'(\s+&&\s+|\s+\|\|\s+)', expression)
            if len(parts) > 1:
                parts.pop(random.randrange(0, len(parts), 2))  # Remove condition
                if parts and parts[0] in [" && ", " || "]:
                    parts.pop(0)  # Remove leading operator
                expression = "".join(parts)
        
        elif mutation_type == "modify":
            # Modify an existing condition
            if "==" in expression:
                # Change comparison value
                pattern = r'(\w+)\s*==\s*(\w+)'
                def replace_value(match):
                    field = match.group(1)
                    if "port" in field:
                        return f"{field} == {random.choice([22, 80, 443, 3389])}"
                    return match.group(0)
                expression = re.sub(pattern, replace_value, expression, count=1)
        
        return FilterRule(
            rule_id=f"rule_{self.generation}_{random.randint(1000, 9999)}",
            expression=expression,
            priority=rule.priority,
            fitness_score=0.0,
            matches=0,
            false_positives=0,
            generation=self.generation,
            parent_ids=[rule.rule_id],
            metadata={"type": "mutation", "mutation_type": mutation_type}
        )
    
    def evolve_generation(self, packet_data: List[NetworkPacket]) -> List[FilterRule]:
        """Evolve the population to the next generation"""
        # Evaluate fitness for all rules
        for rule in self.population:
            self.evaluate_fitness(rule, packet_data)
        
        # Sort by fitness
        self.population.sort(key=lambda x: x.fitness_score, reverse=True)
        
        # Keep best filters
        elite_count = int(self.population_size * self.elitism_rate)
        new_population = self.population[:elite_count]
        
        # Store best filters
        self.best_filters = self.population[:5]
        
        # Generate offspring
        while len(new_population) < self.population_size:
            # Tournament selection
            parent1 = self._tournament_selection()
            parent2 = self._tournament_selection()
            
            # Crossover
            offspring = self.crossover(parent1, parent2)
            
            # Mutation
            offspring = self.mutate(offspring)
            
            new_population.append(offspring)
        
        self.generation += 1
        self.population = new_population
        return new_population
    
    def _tournament_selection(self, tournament_size: int = 3) -> FilterRule:
        """Select parent using tournament selection"""
        tournament = random.sample(self.population, min(tournament_size, len(self.population)))
        return max(tournament, key=lambda x: x.fitness_score)


class WiresharkMonitor:
    """Main Wireshark monitoring system with genetic optimization"""
    
    def __init__(self, 
                 interface: str = None,
                 capture_dir: str = "./captures",
                 db_file: str = "./network_monitor.db"):
        """
        Initialize Wireshark monitor
        
        Args:
            interface: Network interface to monitor (None for default)
            capture_dir: Directory to store packet captures
            db_file: SQLite database file
        """
        self.interface = interface or self._get_default_interface()
        self.capture_dir = Path(capture_dir)
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.db_file = db_file
        
        # Initialize components
        self.genetic_optimizer = GeneticFilterOptimizer()
        self.packet_queue = queue.Queue()
        self.capture_process = None
        self.is_monitoring = False
        
        # Initialize database
        self._init_database()
        
        # Verify Wireshark/tshark installation
        self._verify_wireshark()
    
    def _get_default_interface(self) -> str:
        """Get default network interface"""
        if sys.platform == "win32":
            # On Windows, get first Ethernet interface
            try:
                result = subprocess.run(["tshark", "-D"], 
                                      capture_output=True, text=True, check=True)
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'Ethernet' in line or 'Wi-Fi' in line:
                        # Extract interface number
                        return line.split('.')[0]
                return "1"  # Default to first interface
            except:
                return "1"
        else:
            return "eth0"  # Default for Linux
    
    def _verify_wireshark(self):
        """Verify Wireshark/tshark is installed"""
        try:
            result = subprocess.run(["tshark", "-v"], 
                                  capture_output=True, text=True, check=True)
            print(f"[INFO] Found tshark: {result.stdout.split()[1]}")
        except FileNotFoundError:
            print("[WARNING] tshark not found. Please ensure Wireshark is installed.")
            print("         Download from: https://www.wireshark.org/download.html")
            print("         Make sure tshark is in your PATH")
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                packet_type TEXT,
                size INTEGER,
                payload_hash TEXT,
                flags TEXT,
                threat_level INTEGER,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS filter_rules (
                rule_id TEXT PRIMARY KEY,
                expression TEXT,
                priority INTEGER,
                fitness_score REAL,
                matches INTEGER,
                false_positives INTEGER,
                generation INTEGER,
                parent_ids TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                anomaly_type TEXT,
                severity INTEGER,
                source_ip TEXT,
                dest_ip TEXT,
                description TEXT,
                filter_rule_id TEXT,
                packet_ids TEXT,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                session_id TEXT PRIMARY KEY,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                interface TEXT,
                packets_captured INTEGER,
                anomalies_detected INTEGER,
                filters_evolved INTEGER,
                metadata TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def start_capture(self, 
                     duration: int = 60,
                     filter_expression: str = None,
                     output_file: str = None) -> str:
        """
        Start packet capture using tshark
        
        Args:
            duration: Capture duration in seconds
            filter_expression: Wireshark display filter
            output_file: Output pcap file
        
        Returns:
            Path to capture file
        """
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.capture_dir / f"capture_{timestamp}.pcap"
        
        cmd = [
            "tshark",
            "-i", str(self.interface),
            "-a", f"duration:{duration}",
            "-w", str(output_file)
        ]
        
        if filter_expression:
            cmd.extend(["-f", filter_expression])
        
        print(f"[INFO] Starting capture on interface {self.interface}")
        print(f"       Output: {output_file}")
        
        try:
            self.capture_process = subprocess.Popen(cmd, 
                                                   stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE)
            self.is_monitoring = True
            
            # Wait for capture to complete
            stdout, stderr = self.capture_process.communicate(timeout=duration + 5)
            
            if self.capture_process.returncode != 0:
                print(f"[ERROR] Capture failed: {stderr.decode()}")
                return None
            
            print(f"[INFO] Capture completed: {output_file}")
            return str(output_file)
            
        except subprocess.TimeoutExpired:
            self.capture_process.kill()
            print("[WARNING] Capture timed out")
            return str(output_file)
        except Exception as e:
            print(f"[ERROR] Capture failed: {e}")
            return None
        finally:
            self.is_monitoring = False
    
    def analyze_capture(self, pcap_file: str) -> List[NetworkPacket]:
        """
        Analyze captured packets
        
        Args:
            pcap_file: Path to pcap file
        
        Returns:
            List of analyzed packets
        """
        packets = []
        
        # Use tshark to read and parse packets
        cmd = [
            "tshark",
            "-r", pcap_file,
            "-T", "json",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "ip.proto",
            "-e", "frame.len",
            "-e", "tcp.flags"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            packet_data = json.loads(result.stdout)
            
            for pkt in packet_data:
                layers = pkt.get("_source", {}).get("layers", {})
                
                # Extract packet information
                timestamp = layers.get("frame.time", [""])[0]
                source_ip = layers.get("ip.src", [""])[0]
                dest_ip = layers.get("ip.dst", [""])[0]
                
                # Determine ports
                source_port = None
                dest_port = None
                if "tcp.srcport" in layers:
                    source_port = int(layers["tcp.srcport"][0])
                    dest_port = int(layers["tcp.dstport"][0])
                elif "udp.srcport" in layers:
                    source_port = int(layers["udp.srcport"][0])
                    dest_port = int(layers["udp.dstport"][0])
                
                # Determine protocol
                proto_num = layers.get("ip.proto", [""])[0]
                protocol = self._get_protocol_name(proto_num)
                
                # Determine packet type
                packet_type = self._classify_packet(protocol, dest_port)
                
                # Calculate threat level
                threat_level = self._assess_threat(source_ip, dest_ip, 
                                                  source_port, dest_port, 
                                                  protocol)
                
                # Create packet object
                packet = NetworkPacket(
                    timestamp=datetime.datetime.now(),  # Simplified
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    source_port=source_port,
                    dest_port=dest_port,
                    protocol=protocol,
                    packet_type=packet_type,
                    size=int(layers.get("frame.len", [0])[0]),
                    payload_hash=hashlib.md5(str(pkt).encode()).hexdigest(),
                    flags=self._parse_tcp_flags(layers.get("tcp.flags", [""])[0]),
                    threat_level=threat_level,
                    metadata={}
                )
                
                packets.append(packet)
                self._save_packet_to_db(packet)
            
            print(f"[INFO] Analyzed {len(packets)} packets")
            return packets
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to analyze capture: {e}")
            return []
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse packet data: {e}")
            return []
    
    def _get_protocol_name(self, proto_num: str) -> str:
        """Convert protocol number to name"""
        protocols = {
            "1": "ICMP",
            "6": "TCP",
            "17": "UDP",
            "41": "IPv6",
            "47": "GRE",
            "50": "ESP",
            "51": "AH"
        }
        return protocols.get(proto_num, "OTHER")
    
    def _classify_packet(self, protocol: str, dest_port: Optional[int]) -> PacketType:
        """Classify packet type based on protocol and port"""
        if protocol == "TCP":
            if dest_port == 80:
                return PacketType.HTTP
            elif dest_port == 443:
                return PacketType.HTTPS
            elif dest_port == 22:
                return PacketType.SSH
            elif dest_port == 21:
                return PacketType.FTP
            elif dest_port == 25 or dest_port == 587:
                return PacketType.SMTP
            else:
                return PacketType.TCP
        elif protocol == "UDP":
            if dest_port == 53:
                return PacketType.DNS
            elif dest_port == 67 or dest_port == 68:
                return PacketType.DHCP
            else:
                return PacketType.UDP
        elif protocol == "ICMP":
            return PacketType.ICMP
        else:
            return PacketType.OTHER
    
    def _parse_tcp_flags(self, flags_hex: str) -> List[str]:
        """Parse TCP flags from hex value"""
        if not flags_hex:
            return []
        
        try:
            flags_int = int(flags_hex, 16)
            flags = []
            if flags_int & 0x01: flags.append("FIN")
            if flags_int & 0x02: flags.append("SYN")
            if flags_int & 0x04: flags.append("RST")
            if flags_int & 0x08: flags.append("PSH")
            if flags_int & 0x10: flags.append("ACK")
            if flags_int & 0x20: flags.append("URG")
            return flags
        except:
            return []
    
    def _assess_threat(self, 
                      source_ip: str, 
                      dest_ip: str,
                      source_port: Optional[int],
                      dest_port: Optional[int],
                      protocol: str) -> ThreatLevel:
        """Assess threat level of a packet"""
        # Simplified threat assessment
        threat_score = 0
        
        # Check for suspicious ports
        suspicious_ports = [23, 135, 139, 445, 1433, 3389, 4444, 5900]
        if dest_port in suspicious_ports or source_port in suspicious_ports:
            threat_score += 2
        
        # Check for private IP communication
        if self._is_private_ip(source_ip) and not self._is_private_ip(dest_ip):
            threat_score += 1
        
        # Check for scanning patterns
        if dest_port and dest_port > 1024 and protocol == "TCP":
            threat_score += 1
        
        # Map score to threat level
        if threat_score >= 4:
            return ThreatLevel.HIGH
        elif threat_score >= 3:
            return ThreatLevel.MEDIUM
        elif threat_score >= 1:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        if not ip:
            return False
        
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            # Check private IP ranges
            if parts[0] == "10":
                return True
            if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
                return True
            if parts[0] == "192" and parts[1] == "168":
                return True
            return False
        except:
            return False
    
    def evolve_filters(self, packets: List[NetworkPacket], generations: int = 10):
        """
        Evolve filter rules using genetic algorithm
        
        Args:
            packets: List of captured packets
            generations: Number of generations to evolve
        """
        print("[INFO] Starting genetic filter evolution")
        
        # Initialize population
        self.genetic_optimizer.initialize_population()
        
        # Evolve for specified generations
        for gen in range(generations):
            print(f"[INFO] Generation {gen + 1}/{generations}")
            
            # Evolve population
            population = self.genetic_optimizer.evolve_generation(packets)
            
            # Save best filters to database
            for filter_rule in self.genetic_optimizer.best_filters[:3]:
                self._save_filter_to_db(filter_rule)
            
            # Display best filter
            best = self.genetic_optimizer.best_filters[0]
            print(f"       Best filter: {best.expression}")
            print(f"       Fitness: {best.fitness_score:.3f}")
        
        print("[INFO] Filter evolution completed")
        return self.genetic_optimizer.best_filters
    
    def detect_anomalies(self, packets: List[NetworkPacket]) -> List[Dict[str, Any]]:
        """
        Detect anomalies in network traffic
        
        Args:
            packets: List of network packets
        
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        # Port scan detection
        port_scan = self._detect_port_scan(packets)
        if port_scan:
            anomalies.extend(port_scan)
        
        # SYN flood detection
        syn_flood = self._detect_syn_flood(packets)
        if syn_flood:
            anomalies.extend(syn_flood)
        
        # Large data transfer detection
        large_transfer = self._detect_large_transfer(packets)
        if large_transfer:
            anomalies.extend(large_transfer)
        
        # DNS tunneling detection
        dns_tunnel = self._detect_dns_tunneling(packets)
        if dns_tunnel:
            anomalies.extend(dns_tunnel)
        
        # Save anomalies to database
        for anomaly in anomalies:
            self._save_anomaly_to_db(anomaly)
        
        print(f"[INFO] Detected {len(anomalies)} anomalies")
        return anomalies
    
    def _detect_port_scan(self, packets: List[NetworkPacket]) -> List[Dict[str, Any]]:
        """Detect port scanning activity"""
        anomalies = []
        ip_port_map = {}
        
        for packet in packets:
            if packet.protocol == "TCP" and "SYN" in packet.flags:
                key = packet.source_ip
                if key not in ip_port_map:
                    ip_port_map[key] = set()
                if packet.dest_port:
                    ip_port_map[key].add(packet.dest_port)
        
        # Check for IPs scanning multiple ports
        for ip, ports in ip_port_map.items():
            if len(ports) > 10:  # Threshold for port scan
                anomalies.append({
                    "timestamp": datetime.datetime.now(),
                    "anomaly_type": "PORT_SCAN",
                    "severity": ThreatLevel.HIGH.value,
                    "source_ip": ip,
                    "dest_ip": "",
                    "description": f"Port scan detected from {ip} to {len(ports)} ports",
                    "metadata": {"ports_scanned": list(ports)}
                })
        
        return anomalies
    
    def _detect_syn_flood(self, packets: List[NetworkPacket]) -> List[Dict[str, Any]]:
        """Detect SYN flood attacks"""
        anomalies = []
        syn_count = {}
        
        for packet in packets:
            if packet.protocol == "TCP" and "SYN" in packet.flags and "ACK" not in packet.flags:
                key = f"{packet.source_ip}->{packet.dest_ip}"
                syn_count[key] = syn_count.get(key, 0) + 1
        
        # Check for excessive SYN packets
        for connection, count in syn_count.items():
            if count > 50:  # Threshold for SYN flood
                source, dest = connection.split("->")
                anomalies.append({
                    "timestamp": datetime.datetime.now(),
                    "anomaly_type": "SYN_FLOOD",
                    "severity": ThreatLevel.CRITICAL.value,
                    "source_ip": source,
                    "dest_ip": dest,
                    "description": f"Possible SYN flood: {count} SYN packets",
                    "metadata": {"syn_count": count}
                })
        
        return anomalies
    
    def _detect_large_transfer(self, packets: List[NetworkPacket]) -> List[Dict[str, Any]]:
        """Detect unusually large data transfers"""
        anomalies = []
        transfer_size = {}
        
        for packet in packets:
            key = f"{packet.source_ip}->{packet.dest_ip}"
            transfer_size[key] = transfer_size.get(key, 0) + packet.size
        
        # Check for large transfers
        for connection, size in transfer_size.items():
            if size > 100_000_000:  # 100MB threshold
                source, dest = connection.split("->")
                anomalies.append({
                    "timestamp": datetime.datetime.now(),
                    "anomaly_type": "LARGE_TRANSFER",
                    "severity": ThreatLevel.MEDIUM.value,
                    "source_ip": source,
                    "dest_ip": dest,
                    "description": f"Large data transfer: {size / 1_000_000:.2f} MB",
                    "metadata": {"transfer_size": size}
                })
        
        return anomalies
    
    def _detect_dns_tunneling(self, packets: List[NetworkPacket]) -> List[Dict[str, Any]]:
        """Detect potential DNS tunneling"""
        anomalies = []
        dns_queries = {}
        
        for packet in packets:
            if packet.packet_type == PacketType.DNS:
                key = packet.source_ip
                dns_queries[key] = dns_queries.get(key, 0) + 1
        
        # Check for excessive DNS queries
        for ip, count in dns_queries.items():
            if count > 100:  # Threshold for DNS tunneling
                anomalies.append({
                    "timestamp": datetime.datetime.now(),
                    "anomaly_type": "DNS_TUNNELING",
                    "severity": ThreatLevel.HIGH.value,
                    "source_ip": ip,
                    "dest_ip": "",
                    "description": f"Possible DNS tunneling: {count} queries",
                    "metadata": {"query_count": count}
                })
        
        return anomalies
    
    def _save_packet_to_db(self, packet: NetworkPacket):
        """Save packet to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO packets 
            (timestamp, source_ip, dest_ip, source_port, dest_port, protocol,
             packet_type, size, payload_hash, flags, threat_level, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet.timestamp,
            packet.source_ip,
            packet.dest_ip,
            packet.source_port,
            packet.dest_port,
            packet.protocol,
            packet.packet_type.value,
            packet.size,
            packet.payload_hash,
            json.dumps(packet.flags),
            packet.threat_level.value,
            json.dumps(packet.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _save_filter_to_db(self, filter_rule: FilterRule):
        """Save filter rule to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO filter_rules 
            (rule_id, expression, priority, fitness_score, matches,
             false_positives, generation, parent_ids, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            filter_rule.rule_id,
            filter_rule.expression,
            filter_rule.priority,
            filter_rule.fitness_score,
            filter_rule.matches,
            filter_rule.false_positives,
            filter_rule.generation,
            json.dumps(filter_rule.parent_ids),
            json.dumps(filter_rule.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _save_anomaly_to_db(self, anomaly: Dict[str, Any]):
        """Save anomaly to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO anomalies 
            (timestamp, anomaly_type, severity, source_ip, dest_ip,
             description, filter_rule_id, packet_ids, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            anomaly["timestamp"],
            anomaly["anomaly_type"],
            anomaly["severity"],
            anomaly["source_ip"],
            anomaly["dest_ip"],
            anomaly["description"],
            anomaly.get("filter_rule_id", ""),
            json.dumps(anomaly.get("packet_ids", [])),
            json.dumps(anomaly.get("metadata", {}))
        ))
        
        conn.commit()
        conn.close()
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate monitoring report"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get packet statistics
        cursor.execute("SELECT COUNT(*) FROM packets")
        total_packets = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM packets WHERE threat_level >= ?", 
                      (ThreatLevel.MEDIUM.value,))
        suspicious_packets = cursor.fetchone()[0]
        
        # Get anomaly statistics
        cursor.execute("SELECT COUNT(*) FROM anomalies")
        total_anomalies = cursor.fetchone()[0]
        
        cursor.execute("SELECT anomaly_type, COUNT(*) FROM anomalies GROUP BY anomaly_type")
        anomaly_breakdown = dict(cursor.fetchall())
        
        # Get best filters
        cursor.execute('''
            SELECT expression, fitness_score 
            FROM filter_rules 
            ORDER BY fitness_score DESC 
            LIMIT 5
        ''')
        best_filters = cursor.fetchall()
        
        conn.close()
        
        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "statistics": {
                "total_packets": total_packets,
                "suspicious_packets": suspicious_packets,
                "total_anomalies": total_anomalies,
                "threat_ratio": suspicious_packets / max(1, total_packets)
            },
            "anomaly_breakdown": anomaly_breakdown,
            "best_filters": [
                {"expression": f[0], "fitness": f[1]} for f in best_filters
            ]
        }
        
        return report


# Example usage
if __name__ == "__main__":
    print("="*60)
    print("WIRESHARK GENETIC NETWORK MONITOR")
    print("="*60)
    
    # Initialize monitor
    monitor = WiresharkMonitor()
    
    print("\n[1] Starting packet capture...")
    # Note: This requires admin/root privileges
    capture_file = monitor.start_capture(duration=30, filter_expression="tcp or udp")
    
    if capture_file:
        print("\n[2] Analyzing captured packets...")
        packets = monitor.analyze_capture(capture_file)
        
        if packets:
            print("\n[3] Evolving optimal filters...")
            best_filters = monitor.evolve_filters(packets, generations=5)
            
            print("\n[4] Detecting anomalies...")
            anomalies = monitor.detect_anomalies(packets)
            
            print("\n[5] Generating report...")
            report = monitor.generate_report()
            
            print("\n" + "="*60)
            print("MONITORING REPORT")
            print("="*60)
            print(json.dumps(report, indent=2, default=str))
            
            print("\n[INFO] Monitoring data saved to:", monitor.db_file)
    else:
        print("[WARNING] No capture file available.")
        print("          Ensure Wireshark/tshark is installed and you have admin privileges.")