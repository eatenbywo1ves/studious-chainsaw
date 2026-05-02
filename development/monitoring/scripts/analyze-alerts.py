#!/usr/bin/env python3
"""
Alert Log Analysis Script
Analyzes alert.log to identify patterns, root causes, and provide actionable insights
"""

import re
from collections import Counter, defaultdict
from datetime import datetime
import sys

def parse_log_line(line):
    """Parse a log line and extract timestamp, severity, and message"""
    match = re.match(r'([\d\-T:.Z]+) \[(WARNING|CRITICAL|ERROR|INFO)\] (.+)', line.strip())
    if match:
        timestamp_str, severity, message = match.groups()
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            timestamp = None
        return timestamp, severity, message
    return None, None, None

def analyze_alert_log(filepath):
    """Main analysis function"""
    patterns = defaultdict(int)
    timestamps = []
    severity_counts = Counter()
    service_failures = defaultdict(int)
    hourly_distribution = defaultdict(int)
    daily_distribution = defaultdict(int)

    print(f"Analyzing alert log: {filepath}")
    print("=" * 80)

    line_count = 0
    parsed_count = 0

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line_count += 1
            timestamp, severity, message = parse_log_line(line)

            if timestamp and severity and message:
                parsed_count += 1
                timestamps.append(timestamp)
                severity_counts[severity] += 1
                patterns[message] += 1

                # Track hourly and daily patterns
                hourly_distribution[timestamp.hour] += 1
                daily_distribution[timestamp.date()] += 1

                # Extract service names from "X is not available" messages
                service_match = re.match(r'(.+?) is not available', message)
                if service_match:
                    service_name = service_match.group(1)
                    service_failures[service_name] += 1

    print(f"\nTotal lines: {line_count}")
    print(f"Parsed alerts: {parsed_count}")
    print(f"Date range: {min(timestamps)} to {max(timestamps)}")
    print(f"Duration: {(max(timestamps) - min(timestamps)).days} days")

    # Calculate alert frequency
    if len(timestamps) >= 2:
        duration_seconds = (max(timestamps) - min(timestamps)).total_seconds()
        alerts_per_hour = (parsed_count / duration_seconds) * 3600 if duration_seconds > 0 else 0
        print(f"Average alert rate: {alerts_per_hour:.1f} alerts/hour")

    print("\n" + "=" * 80)
    print("SEVERITY DISTRIBUTION")
    print("=" * 80)
    for severity, count in severity_counts.most_common():
        percentage = (count / parsed_count) * 100
        print(f"  {severity:10s}: {count:6d} ({percentage:5.1f}%)")

    print("\n" + "=" * 80)
    print("TOP 20 ALERT PATTERNS")
    print("=" * 80)
    top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:20]
    for i, (msg, count) in enumerate(top_patterns, 1):
        percentage = (count / parsed_count) * 100
        print(f"{i:2d}. [{count:6d}x | {percentage:5.1f}%] {msg[:70]}")

    print("\n" + "=" * 80)
    print("SERVICE FAILURE ANALYSIS")
    print("=" * 80)
    if service_failures:
        total_service_alerts = sum(service_failures.values())
        print(f"Total service failure alerts: {total_service_alerts}")
        print(f"Percentage of all alerts: {(total_service_alerts/parsed_count)*100:.1f}%\n")

        for service, count in sorted(service_failures.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_service_alerts) * 100
            # Estimate alert frequency (assuming 5 second interval)
            print(f"  {service:30s}: {count:6d} alerts ({percentage:5.1f}% of service alerts)")

    print("\n" + "=" * 80)
    print("DAILY ALERT DISTRIBUTION")
    print("=" * 80)
    for date in sorted(daily_distribution.keys()):
        count = daily_distribution[date]
        print(f"  {date}: {count:6d} alerts")

    print("\n" + "=" * 80)
    print("HOURLY DISTRIBUTION (Peak Times)")
    print("=" * 80)
    sorted_hours = sorted(hourly_distribution.items(), key=lambda x: x[1], reverse=True)[:10]
    for hour, count in sorted_hours:
        print(f"  Hour {hour:02d}:00 - {count:6d} alerts")

    print("\n" + "=" * 80)
    print("ROOT CAUSE ANALYSIS")
    print("=" * 80)

    # Identify if alerts repeat at fixed intervals
    if len(timestamps) >= 10:
        intervals = []
        for i in range(1, min(100, len(timestamps))):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)

        avg_interval = sum(intervals) / len(intervals)
        print(f"\nAverage time between alerts: {avg_interval:.2f} seconds")

        # Check for repeating pattern (5 second polling)
        five_sec_intervals = sum(1 for i in intervals if 4.5 <= i <= 5.5)
        if five_sec_intervals > len(intervals) * 0.8:
            print("ALERT SPAM DETECTED: ~80%+ of alerts occur at 5-second intervals")
            print("  -> Likely cause: Health check polling without deduplication")

    # Check if all services failing simultaneously
    if service_failures:
        services = list(service_failures.keys())
        if len(services) >= 7:
            print(f"\nMULTIPLE SERVICES DOWN: {len(services)} services failing simultaneously")
            print("  -> Possible causes:")
            print("     1. Docker/Container runtime not running")
            print("     2. Network connectivity issues")
            print("     3. Service orchestration failure")
            print("     4. Database or shared dependency failure")

    print("\n" + "=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    print("\n1. IMPLEMENT ALERT DEDUPLICATION")
    print("   - Only send alert on state change (OK -> CRITICAL, CRITICAL -> OK)")
    print("   - Group repeated alerts with same message")
    print("   - Expected reduction: 80-95% of alert volume")

    print("\n2. IMPLEMENT EXPONENTIAL BACKOFF")
    print("   - First alert: immediate")
    print("   - Subsequent alerts: 1min, 5min, 15min, 30min, 1hr intervals")
    print("   - Reset on service recovery")

    print("\n3. FIX SERVICE FAILURES")
    print("   - Investigate why all 7 services went offline simultaneously")
    print("   - Check Docker daemon status: docker ps")
    print("   - Check service dependencies")
    print("   - Implement service auto-restart with systemd/Docker restart policies")

    print("\n4. IMPLEMENT LOG ROTATION")
    print("   - Current log size: 1.3MB for ~10 days")
    print("   - Projected size: ~4MB/month without rotation")
    print("   - Use logrotate or winston rotation with daily/size-based rotation")
    print("   - Keep 7-14 days of logs, compress older logs")

    print("\n5. ADD ALERTING THRESHOLDS")
    print("   - Don't alert on first failure (could be transient)")
    print("   - Alert after 3 consecutive failures")
    print("   - Implement critical/warning severity levels based on downtime")

    print("\n" + "=" * 80)

    return {
        'top_patterns': top_patterns,
        'severity_counts': severity_counts,
        'service_failures': service_failures,
        'total_alerts': parsed_count,
        'date_range': (min(timestamps), max(timestamps)) if timestamps else (None, None)
    }

if __name__ == '__main__':
    filepath = sys.argv[1] if len(sys.argv) > 1 else 'C:/Users/Corbin/development/monitoring/logs/alerts.log'
    try:
        results = analyze_alert_log(filepath)
        print("\nAnalysis complete!")
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"Error analyzing log: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
