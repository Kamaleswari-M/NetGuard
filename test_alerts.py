from detector import detect_port_scan, detect_icmp_flood
from database import create_tables, save_alert


create_tables()

print("=" * 65)
print("          NETGUARD SECURITY ALERT TEST")
print("=" * 65)


# =====================================================
# TEST 1 - PORT SCAN DETECTION
# =====================================================

print("\n[TEST 1] Simulating suspicious port activity...\n")

test_ip = "192.168.1.100"

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

port_alert_saved = False

for port in test_ports:

    print(f"Testing TCP connection -> Port {port}")

    alert = detect_port_scan(
        test_ip,
        port
    )

    if alert and not port_alert_saved:

        print("\n🚨 PORT SCAN DETECTED")
        print(alert)

        save_alert(
            "PORT_SCAN",
            test_ip,
            "HIGH",
            alert
        )

        port_alert_saved = True


# =====================================================
# TEST 2 - ICMP FLOOD DETECTION
# =====================================================

print("\n" + "-" * 65)

print("\n[TEST 2] Simulating abnormal ICMP activity...\n")

icmp_test_ip = "192.168.1.200"

icmp_alert_saved = False

for packet_number in range(15):

    print(
        f"Testing ICMP packet "
        f"{packet_number + 1}"
    )

    alert = detect_icmp_flood(
        icmp_test_ip
    )

    if alert and not icmp_alert_saved:

        print("\n🚨 ICMP FLOOD DETECTED")
        print(alert)

        save_alert(
            "ICMP_FLOOD",
            icmp_test_ip,
            "HIGH",
            alert
        )

        icmp_alert_saved = True


print("\n" + "=" * 65)
print("TEST COMPLETED")
print("Check the NetGuard dashboard for security alerts.")
print("=" * 65)