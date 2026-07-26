from detector import detect_icmp_flood


source_ip = "192.168.1.200"

print("=" * 60)
print("NETGUARD ICMP FLOOD DETECTOR TEST")
print("=" * 60)


for i in range(15):

    print(f"Testing ICMP packet {i + 1}")

    alert = detect_icmp_flood(source_ip)

    if alert:

        print("\n" + "!" * 60)
        print("🚨 SECURITY ALERT")
        print(alert)
        print("!" * 60)