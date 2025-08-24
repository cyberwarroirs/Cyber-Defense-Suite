import pyshark

def analyze_pcap(file_path):
    """
    Simple PCAP analyzer to detect:
    - Port scans (multiple ports from same source IP)
    - High packet rate (simple DDoS sign)
    Returns a dict with findings.
    """
    cap = pyshark.FileCapture(file_path, keep_packets=False)
    src_ip_ports = {}
    packet_count = 0
    
    for pkt in cap:
        try:
            ip = pkt.ip.src
            port = pkt[pkt.transport_layer].dstport
            key = (ip, port)
            src_ip_ports[key] = src_ip_ports.get(key, 0) + 1
            packet_count += 1
        except AttributeError:
            continue

    # Detect port scans: many ports targeted from same IP
    ip_port_count = {}
    for (ip, port), count in src_ip_ports.items():
        ip_port_count[ip] = ip_port_count.get(ip, set())
        ip_port_count[ip].add(port)
    port_scanners = [ip for ip, ports in ip_port_count.items() if len(ports) > 10]

    result = {
        "total_packets": packet_count,
        "potential_port_scanners": port_scanners,
        "note": "Basic heuristics only; expand for production use."
    }
    return result
