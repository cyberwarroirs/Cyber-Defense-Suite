import scapy.all as scapy
from collections import Counter

def live_monitor(interface, duration=15):
    alerts = []
    details = []  # Detailed info

    packets = scapy.sniff(iface=interface, timeout=duration)
    alerts.append(f"ℹ️ Packets captured during monitoring: {len(packets)}")

    syn_counter = Counter()
    for pkt in packets:
        if pkt.haslayer(scapy.IP):
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            proto = "TCP" if pkt.haslayer(scapy.TCP) else "Other"

            if pkt.haslayer(scapy.TCP):
                flags = pkt[scapy.TCP].flags
                sport = pkt[scapy.TCP].sport
                dport = pkt[scapy.TCP].dport

                # Log SYN packets
                if flags == 'S':
                    syn_counter[src] += 1
                    details.append(f"SYN from {src}:{sport} → {dst}:{dport}")

                # Log any TCP packet
                details.append(f"{proto} {src}:{sport} → {dst}:{dport}, Flags={flags}")
            else:
                details.append(f"{proto} {src} → {dst}")

    alerts.append(f"ℹ️ Unique IPs sending SYN packets: {len(syn_counter)}")

    for ip, count in syn_counter.items():
        if count > 20:
            alerts.append(f"⚠️ High SYN rate (DDoS/scan) from {ip}: {count} SYN packets")

    if not any(alert.startswith("⚠️") for alert in alerts):
        alerts.append("✔️ No suspicious SYN flood activity detected.")

    return alerts, details
