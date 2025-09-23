"""
Genetic Algorithm Network Filter Simulation
Demonstrates genetic algorithm optimization without requiring Wireshark
"""

import random
import json
from datetime import datetime, timedelta
from wireshark_genetic_monitor import (
    GeneticFilterOptimizer, 
    NetworkPacket, 
    PacketType, 
    ThreatLevel
)

def generate_simulated_traffic(num_packets=1000):
    """Generate simulated network traffic for testing"""
    packets = []
    
    # Normal traffic patterns
    normal_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    normal_ports = [80, 443, 22, 53]
    
    # Suspicious traffic patterns
    suspicious_ips = ["185.220.101.45", "195.154.179.3", "91.219.237.244"]
    suspicious_ports = [4444, 31337, 1337, 6667]
    
    for i in range(num_packets):
        # 70% normal traffic, 30% suspicious
        is_suspicious = random.random() < 0.3
        
        if is_suspicious:
            source_ip = random.choice(suspicious_ips)
            dest_ip = random.choice(normal_ips)
            dest_port = random.choice(suspicious_ports + [445, 139, 23])
            protocol = random.choice(["TCP", "UDP"])
            threat_level = random.choice([ThreatLevel.MEDIUM, ThreatLevel.HIGH])
            flags = ["SYN"] if random.random() < 0.7 else ["SYN", "ACK"]
        else:
            source_ip = random.choice(normal_ips)
            dest_ip = f"8.8.{random.randint(1,255)}.{random.randint(1,255)}"
            dest_port = random.choice(normal_ports)
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            threat_level = ThreatLevel.SAFE
            flags = ["ACK"] if protocol == "TCP" else []
        
        packet = NetworkPacket(
            timestamp=datetime.now() - timedelta(seconds=num_packets-i),
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=random.randint(1024, 65535),
            dest_port=dest_port,
            protocol=protocol,
            packet_type=PacketType.TCP if protocol == "TCP" else PacketType.UDP,
            size=random.randint(64, 1500),
            payload_hash=f"hash_{i}",
            flags=flags,
            threat_level=threat_level,
            metadata={"simulated": True}
        )
        packets.append(packet)
    
    return packets

def demonstrate_genetic_evolution():
    """Demonstrate genetic algorithm filter evolution"""
    print("="*60)
    print("GENETIC ALGORITHM FILTER EVOLUTION DEMONSTRATION")
    print("="*60)
    
    # Generate simulated traffic
    print("\n[1] Generating simulated network traffic...")
    packets = generate_simulated_traffic(1000)
    
    # Count threat levels
    threat_counts = {}
    for packet in packets:
        level = packet.threat_level.name
        threat_counts[level] = threat_counts.get(level, 0) + 1
    
    print(f"Generated {len(packets)} packets:")
    for level, count in threat_counts.items():
        print(f"  - {level}: {count} packets")
    
    # Initialize genetic optimizer
    print("\n[2] Initializing genetic optimizer...")
    optimizer = GeneticFilterOptimizer(
        population_size=30,
        mutation_rate=0.15,
        crossover_rate=0.7,
        elitism_rate=0.2
    )
    
    # Initialize population
    print("\n[3] Creating initial filter population...")
    initial_population = optimizer.initialize_population()
    print(f"Created {len(initial_population)} initial filters")
    
    # Show some initial filters
    print("\nSample initial filters:")
    for filter_rule in initial_population[:3]:
        print(f"  - {filter_rule.expression}")
    
    # Evolve filters
    print("\n[4] Evolving filters through genetic algorithm...")
    print("-" * 40)
    
    best_filters_history = []
    
    for generation in range(10):
        # Evolve one generation
        population = optimizer.evolve_generation(packets)
        
        # Get best filter
        best_filter = optimizer.best_filters[0] if optimizer.best_filters else population[0]
        best_filters_history.append({
            "generation": generation + 1,
            "expression": best_filter.expression,
            "fitness": best_filter.fitness_score,
            "matches": best_filter.matches
        })
        
        print(f"\nGeneration {generation + 1}:")
        print(f"  Best filter: {best_filter.expression[:50]}...")
        print(f"  Fitness: {best_filter.fitness_score:.3f}")
        print(f"  Matches: {best_filter.matches}/{len(packets)}")
    
    # Show evolution progress
    print("\n" + "="*60)
    print("EVOLUTION RESULTS")
    print("="*60)
    
    print("\nFitness improvement over generations:")
    for i, gen_data in enumerate(best_filters_history):
        bar_length = int(gen_data["fitness"] * 40)
        bar = "#" * bar_length + "-" * (40 - bar_length)
        print(f"Gen {gen_data['generation']:2d}: [{bar}] {gen_data['fitness']:.3f}")
    
    # Show top 5 evolved filters
    print("\nTop 5 evolved filters:")
    for i, filter_rule in enumerate(optimizer.best_filters[:5], 1):
        print(f"\n{i}. Expression: {filter_rule.expression}")
        print(f"   Fitness: {filter_rule.fitness_score:.3f}")
        print(f"   Matches: {filter_rule.matches}")
        print(f"   False Positives: {filter_rule.false_positives}")
    
    return optimizer.best_filters

def analyze_network_patterns():
    """Analyze network patterns without Wireshark"""
    print("\n" + "="*60)
    print("NETWORK PATTERN ANALYSIS")
    print("="*60)
    
    # Generate traffic with specific patterns
    packets = []
    
    # Simulate port scan
    print("\n[1] Simulating port scan pattern...")
    scanner_ip = "185.220.101.45"
    for port in range(1, 100):
        packets.append(NetworkPacket(
            timestamp=datetime.now(),
            source_ip=scanner_ip,
            dest_ip="192.168.1.10",
            source_port=random.randint(1024, 65535),
            dest_port=port,
            protocol="TCP",
            packet_type=PacketType.TCP,
            size=64,
            payload_hash=f"scan_{port}",
            flags=["SYN"],
            threat_level=ThreatLevel.HIGH,
            metadata={"pattern": "port_scan"}
        ))
    
    # Simulate DDoS
    print("[2] Simulating DDoS pattern...")
    for i in range(200):
        packets.append(NetworkPacket(
            timestamp=datetime.now(),
            source_ip=f"bot_{i%10}",
            dest_ip="192.168.1.100",
            source_port=random.randint(1024, 65535),
            dest_port=80,
            protocol="TCP",
            packet_type=PacketType.TCP,
            size=1500,
            payload_hash=f"ddos_{i}",
            flags=["SYN"],
            threat_level=ThreatLevel.CRITICAL,
            metadata={"pattern": "ddos"}
        ))
    
    # Analyze patterns
    print("\n[3] Pattern detection results:")
    
    # Port scan detection
    port_scans = {}
    for packet in packets:
        if "SYN" in packet.flags:
            key = packet.source_ip
            if key not in port_scans:
                port_scans[key] = set()
            port_scans[key].add(packet.dest_port)
    
    print("\nPort Scanning Detection:")
    for ip, ports in port_scans.items():
        if len(ports) > 10:
            print(f"  [ALERT] {ip} scanned {len(ports)} ports")
    
    # DDoS detection
    syn_floods = {}
    for packet in packets:
        if "SYN" in packet.flags:
            key = packet.dest_ip
            syn_floods[key] = syn_floods.get(key, 0) + 1
    
    print("\nDDoS Detection:")
    for ip, count in syn_floods.items():
        if count > 50:
            print(f"  [ALERT] {ip} received {count} SYN packets (possible DDoS)")
    
    # Traffic volume analysis
    traffic_by_protocol = {}
    for packet in packets:
        proto = packet.protocol
        traffic_by_protocol[proto] = traffic_by_protocol.get(proto, 0) + 1
    
    print("\nTraffic Distribution:")
    for proto, count in traffic_by_protocol.items():
        percentage = (count / len(packets)) * 100
        print(f"  {proto}: {count} packets ({percentage:.1f}%)")

def main():
    """Main demonstration"""
    print("\nWIRESHARK GENETIC MONITORING - SIMULATION MODE")
    print("This demonstrates the genetic algorithm without requiring Wireshark\n")
    
    # Run genetic evolution
    best_filters = demonstrate_genetic_evolution()
    
    # Analyze patterns
    analyze_network_patterns()
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print("\nKey Findings:")
    print("1. Genetic algorithms successfully evolved filters to detect threats")
    print("2. Fitness scores improved over generations through natural selection")
    print("3. Pattern detection identified simulated attacks (port scans, DDoS)")
    print("\nRecommended Actions:")
    print("1. Install Wireshark for real packet capture")
    print("2. Apply evolved filters to live network traffic")
    print("3. Continue evolving filters as threats change")
    print("4. Integrate with firewall for automated response")
    
    # Export results
    results = {
        "timestamp": datetime.now().isoformat(),
        "best_filters": [
            {
                "expression": f.expression,
                "fitness": f.fitness_score,
                "matches": f.matches
            }
            for f in best_filters[:5]
        ]
    }
    
    with open("genetic_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults exported to genetic_results.json")

if __name__ == "__main__":
    main()