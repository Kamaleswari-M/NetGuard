from detector import detect_port_scan


source_ip = "192.168.1.100"

test_ports = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    443
]


print("=" * 60)
print("NETGUARD PORT SCAN DETECTOR TEST")
print("=" * 60)


for port in test_ports:

    print(f"Testing connection to port {port}")

    alert = detect_port_scan(
        source_ip,
        port
    )

    if alert:

        print("\n" + "!" * 60)
        print("🚨 SECURITY ALERT")
        print(alert)
        print("!" * 60)