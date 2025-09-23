#!/usr/bin/env python3
"""
SMB Traffic Monitoring Agent for EternalBlue Detection
Demonstrates agentic response patterns for network-based exploit detection
"""

import time
import logging
from scapy.all import sniff, TCP, Raw
from collections import defaultdict, deque
import threading
from datetime import datetime, timedelta


class SMBTrafficMonitor:
    """Autonomous agent for monitoring SMB traffic and detecting EternalBlue patterns"""

    def __init__(self, interface="eth0", confidence_threshold=0.8):
        self.interface = interface
        self.confidence_threshold = confidence_threshold
        self.suspicious_patterns = {
            "multiplex_id_82": b"\x00\x52",  # MultiplexID 82 signature
            "trans2_overflow": b"\x00\x32\x00\x00",  # Trans2 request anomaly
            "fea_list_corruption": b"\xff\xfe",  # FEA list manipulation
        }

        self.connection_tracker = defaultdict(dict)
        self.alert_history = deque(maxlen=1000)
        self.behavioral_baselines = {}
        self.running = False

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def start_monitoring(self):
        """Start the autonomous monitoring process"""
        self.running = True
        self.logger.info("SMB Traffic Monitor starting autonomous surveillance...")

        # Start packet capture in separate thread
        capture_thread = threading.Thread(target=self._capture_packets)
        capture_thread.daemon = True
        capture_thread.start()

        # Start behavioral analysis thread
        analysis_thread = threading.Thread(target=self._analyze_behavior)
        analysis_thread.daemon = True
        analysis_thread.start()

        return self

    def _capture_packets(self):
        """Capture and analyze SMB packets"""
        try:
            sniff(
                filter="tcp port 445 or tcp port 139",
                prn=self._process_smb_packet,
                stop_filter=lambda x: not self.running,
                store=False,
            )
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")

    def _process_smb_packet(self, packet):
        """Process individual SMB packets for anomaly detection"""
        if not (TCP in packet and Raw in packet):
            return

        src_ip = packet[0][1].src
        dst_ip = packet[0][1].dst
        payload = bytes(packet[Raw])

        connection_key = f"{src_ip}:{dst_ip}"

        # Update connection tracking
        if connection_key not in self.connection_tracker:
            self.connection_tracker[connection_key] = {
                "first_seen": datetime.now(),
                "packet_count": 0,
                "suspicious_score": 0.0,
                "patterns_detected": [],
            }

        conn_data = self.connection_tracker[connection_key]
        conn_data["packet_count"] += 1
        conn_data["last_seen"] = datetime.now()

        # Analyze packet for EternalBlue indicators
        threat_score = self._analyze_packet_for_threats(payload, conn_data)

        if threat_score > self.confidence_threshold:
            self._trigger_autonomous_response(src_ip, dst_ip, threat_score, conn_data)

    def _analyze_packet_for_threats(self, payload, connection_data):
        """Analyze packet payload for EternalBlue threat indicators"""
        threat_score = 0.0
        detected_patterns = []

        # Check for known EternalBlue signatures
        for pattern_name, signature in self.suspicious_patterns.items():
            if signature in payload:
                threat_score += 0.3
                detected_patterns.append(pattern_name)
                self.logger.warning(f"Detected suspicious pattern: {pattern_name}")

        # Behavioral analysis
        if connection_data["packet_count"] > 50:  # Rapid packet burst
            threat_score += 0.2
            detected_patterns.append("rapid_packet_burst")

        # Protocol anomaly detection
        if self._detect_protocol_anomalies(payload):
            threat_score += 0.4
            detected_patterns.append("protocol_anomaly")

        # Buffer overflow indicators
        if self._detect_buffer_overflow_attempts(payload):
            threat_score += 0.5
            detected_patterns.append("buffer_overflow_attempt")

        connection_data["suspicious_score"] = max(
            connection_data["suspicious_score"], threat_score
        )
        connection_data["patterns_detected"].extend(detected_patterns)

        return threat_score

    def _detect_protocol_anomalies(self, payload):
        """Detect SMB protocol anomalies indicative of exploitation attempts"""
        # Check for malformed SMB headers
        if len(payload) < 4:
            return False

        # Look for SMB magic bytes but with unusual following structure
        if payload.startswith(b"\xffSMB") and len(payload) > 100:
            # Check for unusual command structures
            if payload[8:12] == b"\x00\x00\x00\x00":  # Potential Trans2 manipulation
                return True

        return False

    def _detect_buffer_overflow_attempts(self, payload):
        """Detect potential buffer overflow exploitation attempts"""
        # Look for suspicious patterns in FEA structures
        fea_patterns = [
            b"\x00\x00\xff\xff",  # Integer overflow indicators
            b"\x41\x41\x41\x41",  # Potential shellcode pattern
            b"\x90\x90\x90\x90",  # NOP sled indicators
        ]

        return any(pattern in payload for pattern in fea_patterns)

    def _trigger_autonomous_response(
        self, src_ip, dst_ip, threat_score, connection_data
    ):
        """Execute autonomous defensive response based on threat assessment"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "threat_score": threat_score,
            "patterns_detected": connection_data["patterns_detected"],
            "response_actions": [],
        }

        # Autonomous response escalation based on threat score
        if threat_score >= 0.9:  # High confidence threat
            response_actions = self._execute_level_3_response(src_ip, dst_ip)
        elif threat_score >= 0.7:  # Medium confidence threat
            response_actions = self._execute_level_2_response(src_ip, dst_ip)
        else:  # Low confidence threat
            response_actions = self._execute_level_1_response(src_ip, dst_ip)

        alert["response_actions"] = response_actions
        self.alert_history.append(alert)

        self.logger.critical(f"AUTONOMOUS RESPONSE TRIGGERED: {alert}")

    def _execute_level_1_response(self, src_ip, dst_ip):
        """Level 1: Enhanced monitoring and logging"""
        actions = [
            "enhanced_packet_capture_initiated",
            "behavioral_analysis_intensified",
            "threat_intelligence_correlation_started",
        ]

        # In real implementation, this would interface with network infrastructure
        self.logger.info(
            f"Level 1 Response: Enhanced monitoring for {src_ip} -> {dst_ip}"
        )
        return actions

    def _execute_level_2_response(self, src_ip, dst_ip):
        """Level 2: Traffic throttling and session monitoring"""
        actions = [
            "connection_throttling_applied",
            "session_monitoring_enhanced",
            "security_team_notified",
            "forensic_data_collection_started",
        ]

        # In real implementation, this would interface with firewalls/load balancers
        self.logger.warning(
            f"Level 2 Response: Traffic throttling for {src_ip} -> {dst_ip}"
        )
        return actions

    def _execute_level_3_response(self, src_ip, dst_ip):
        """Level 3: Aggressive blocking and system protection"""
        actions = [
            "source_ip_blocked_immediately",
            "destination_system_isolated",
            "smb_service_disabled_temporarily",
            "emergency_patch_deployment_initiated",
            "incident_response_team_activated",
        ]

        # In real implementation, this would interface with security infrastructure
        self.logger.error(
            f"Level 3 Response: Aggressive blocking for {src_ip} -> {dst_ip}"
        )
        return actions

    def _analyze_behavior(self):
        """Continuous behavioral analysis and baseline updating"""
        while self.running:
            current_time = datetime.now()

            # Clean up old connections
            expired_connections = []
            for conn_key, conn_data in self.connection_tracker.items():
                if current_time - conn_data.get("last_seen", current_time) > timedelta(
                    hours=1
                ):
                    expired_connections.append(conn_key)

            for conn_key in expired_connections:
                del self.connection_tracker[conn_key]

            # Update behavioral baselines
            self._update_behavioral_baselines()

            time.sleep(30)  # Analyze every 30 seconds

    def _update_behavioral_baselines(self):
        """Update behavioral baselines for anomaly detection"""
        if len(self.connection_tracker) < 10:
            return

        packet_counts = [
            conn["packet_count"] for conn in self.connection_tracker.values()
        ]
        avg_packets = sum(packet_counts) / len(packet_counts)

        self.behavioral_baselines["average_packets_per_connection"] = avg_packets
        self.logger.debug(
            f"Updated baseline: avg packets per connection = {avg_packets:.2f}"
        )

    def get_threat_summary(self):
        """Generate current threat assessment summary"""
        active_threats = len(
            [
                conn
                for conn in self.connection_tracker.values()
                if conn["suspicious_score"] > self.confidence_threshold
            ]
        )

        return {
            "active_connections": len(self.connection_tracker),
            "active_threats": active_threats,
            "total_alerts": len(self.alert_history),
            "recent_alerts": (
                list(self.alert_history)[-10:] if self.alert_history else []
            ),
        }

    def stop_monitoring(self):
        """Stop autonomous monitoring"""
        self.running = False
        self.logger.info("SMB Traffic Monitor stopping...")


if __name__ == "__main__":
    # Example usage of the autonomous SMB monitoring agent
    monitor = SMBTrafficMonitor(confidence_threshold=0.7)

    try:
        monitor.start_monitoring()
        print("SMB Traffic Monitor is running autonomously...")
        print("Press Ctrl+C to stop")

        # Simulate continuous operation
        while True:
            time.sleep(10)
            summary = monitor.get_threat_summary()
            print(
                f"Threat Summary: {summary['active_threats']} active threats, "
                f"{summary['active_connections']} connections monitored"
            )

    except KeyboardInterrupt:
        print("\nShutting down SMB Traffic Monitor...")
        monitor.stop_monitoring()
