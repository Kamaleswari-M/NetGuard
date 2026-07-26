import time
from collections import defaultdict


# =========================================================
# CONFIGURATION
# =========================================================

PORT_SCAN_TIME_WINDOW = 10
PORT_THRESHOLD = 10

ICMP_TIME_WINDOW = 10
ICMP_THRESHOLD = 15

# Prevent repeated alerts for the same source
ALERT_COOLDOWN = 30


# =========================================================
# ACTIVITY STORAGE
# =========================================================

port_activity = defaultdict(list)
icmp_activity = defaultdict(list)

# Stores the last time an alert was generated
last_port_scan_alert = {}
last_icmp_alert = {}


# =========================================================
# PORT SCAN DETECTION
# =========================================================

def detect_port_scan(source_ip, destination_port):

    current_time = time.time()

    # Store destination port + timestamp
    port_activity[source_ip].append(
        (destination_port, current_time)
    )

    # Remove entries outside the time window
    port_activity[source_ip] = [
        (port, timestamp)
        for port, timestamp in port_activity[source_ip]
        if current_time - timestamp <= PORT_SCAN_TIME_WINDOW
    ]

    # Count unique destination ports
    unique_ports = {
        port
        for port, timestamp in port_activity[source_ip]
    }

    # Check threshold
    if len(unique_ports) >= PORT_THRESHOLD:

        last_alert_time = last_port_scan_alert.get(
            source_ip,
            0
        )

        # Check cooldown
        if current_time - last_alert_time >= ALERT_COOLDOWN:

            last_port_scan_alert[source_ip] = current_time

            return (
                f"Possible Port Scan | "
                f"Source: {source_ip} | "
                f"Unique Ports: {len(unique_ports)} "
                f"within {PORT_SCAN_TIME_WINDOW} seconds"
            )

    return None


# =========================================================
# ICMP FLOOD DETECTION
# =========================================================

def detect_icmp_flood(source_ip):

    current_time = time.time()

    # Record packet timestamp
    icmp_activity[source_ip].append(current_time)

    # Remove packets outside time window
    icmp_activity[source_ip] = [
        timestamp
        for timestamp in icmp_activity[source_ip]
        if current_time - timestamp <= ICMP_TIME_WINDOW
    ]

    packet_count = len(
        icmp_activity[source_ip]
    )

    # Check threshold
    if packet_count >= ICMP_THRESHOLD:

        last_alert_time = last_icmp_alert.get(
            source_ip,
            0
        )

        # Check cooldown
        if current_time - last_alert_time >= ALERT_COOLDOWN:

            last_icmp_alert[source_ip] = current_time

            return (
                f"Possible ICMP Flood | "
                f"Source: {source_ip} | "
                f"Packets: {packet_count} "
                f"within {ICMP_TIME_WINDOW} seconds"
            )

    return None