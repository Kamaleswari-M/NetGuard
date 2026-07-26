from scapy.all import (
    sniff,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR
)

from detector import (
    detect_port_scan,
    detect_icmp_flood
)

from database import (
    create_tables,
    save_traffic,
    save_alert
)


# =========================================================
# GET IP ADDRESSES
# =========================================================

def get_ips(packet):

    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst

    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst

    return None, None


# =========================================================
# PACKET ANALYSIS
# =========================================================

def analyze_packet(packet):

    source_ip, destination_ip = get_ips(packet)

    if source_ip is None:
        return


    # =====================================================
    # DNS
    # =====================================================

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):

        if packet[DNS].qr == 0:

            domain = packet[DNSQR].qname.decode(
                "utf-8",
                errors="ignore"
            ).rstrip(".")

            print(
                f"[DNS] {source_ip} -> "
                f"{destination_ip} | Query: {domain}"
            )

            save_traffic(
                source_ip,
                destination_ip,
                "DNS",
                details=domain
            )

            return


    # =====================================================
    # TCP
    # =====================================================

    if packet.haslayer(TCP):

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        print(
            f"[TCP] {source_ip}:{source_port} "
            f"-> {destination_ip}:{destination_port}"
        )

        save_traffic(
            source_ip,
            destination_ip,
            "TCP",
            source_port,
            destination_port
        )

        # Only analyze initial SYN packets for port scans
        flags = packet[TCP].flags

        if flags == "S":

            alert = detect_port_scan(
                source_ip,
                destination_port
            )

            if alert:

                print("\n" + "!" * 70)
                print("NETGUARD SECURITY ALERT")
                print(alert)
                print("!" * 70 + "\n")

                save_alert(
                    "PORT_SCAN",
                    source_ip,
                    "HIGH",
                    alert
                )


    # =====================================================
    # UDP
    # =====================================================

    elif packet.haslayer(UDP):

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

        print(
            f"[UDP] {source_ip}:{source_port} "
            f"-> {destination_ip}:{destination_port}"
        )

        save_traffic(
            source_ip,
            destination_ip,
            "UDP",
            source_port,
            destination_port
        )


    # =====================================================
    # ICMP
    # =====================================================

    elif packet.haslayer(ICMP):

        print(
            f"[ICMP] {source_ip} "
            f"-> {destination_ip}"
        )

        save_traffic(
            source_ip,
            destination_ip,
            "ICMP"
        )

        alert = detect_icmp_flood(
            source_ip
        )

        if alert:

            print("\n" + "!" * 70)
            print("NETGUARD SECURITY ALERT")
            print(alert)
            print("!" * 70 + "\n")

            save_alert(
                "ICMP_FLOOD",
                source_ip,
                "HIGH",
                alert
            )


# =========================================================
# START NETGUARD
# =========================================================

create_tables()

print("=" * 70)
print("          NETGUARD - NETWORK INTRUSION DETECTION")
print("=" * 70)

print("\nDatabase initialized successfully.")
print("Detection engine initialized.")
print("Alert cooldown: 30 seconds")

print("\nMonitoring network traffic...")
print("Press Ctrl+C to stop.\n")


try:

    sniff(
        prn=analyze_packet,
        store=False
    )

except KeyboardInterrupt:

    print("\n" + "=" * 70)
    print("NetGuard monitoring stopped.")
    print("=" * 70)