from flask import Flask, render_template, request, flash
import os
import psutil  # For cross-platform network interface listing
from flask_socketio import SocketIO, emit
import threading
from collections import Counter
from log_analyzer.report_generator import generate_log_report
import scapy.all as scapy

# Import backend detection modules
from network_detection.sniffer import analyze_pcap
from network_monitoring.monitor import live_monitor  # 🔥 NEW for real-time monitoring
from host_monitoring.monitor import list_suspicious_processes, check_file_integrity
from log_analyzer.detect_anomalies import detect_log_anomalies
from phishing_detector.phishing_check import is_phishing

app = Flask(__name__)
app.secret_key = 'your_secret_key'
socketio = SocketIO(app, cors_allowed_origins='*')

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Placeholder monitored files with dummy hashes (update with real paths and known hashes)
MONITORED_FILES = {
    '/etc/passwd': 'dummyhash1234567890abcdef',
    # Add more files to monitor here
}

@app.route('/')
def index():
    return render_template('index.html')

# ✅ Network Threat Detection (PCAP upload + Live monitoring)
@app.route('/network', methods=['GET', 'POST'])
def network():
    results = None
    alerts = None
    details = None
    interfaces = list(psutil.net_if_addrs().keys())

    if request.method == 'POST':
        if 'pcap_file' in request.files:
            pcap_file = request.files['pcap_file']
            if pcap_file:
                path = os.path.join(UPLOAD_FOLDER, pcap_file.filename)
                pcap_file.save(path)
                results = analyze_pcap(path)
                flash('✅ PCAP file analyzed successfully.')

        elif 'interface' in request.form:
            interface = request.form['interface']
            if interface not in interfaces:
                flash(f"❌ Interface '{interface}' not found! Please select a valid interface.")
            else:
                try:
                    alerts, details = live_monitor(interface)
                    flash('📡 Live monitoring complete.')
                except Exception as e:
                    flash(f"⚠️ Error during live monitoring: {str(e)}")

    return render_template('network.html', results=results, alerts=alerts, details=details, interfaces=interfaces)

# ✅ Host-Based Threat Detection
@app.route('/host')
def host():
    suspicious_procs, malware_matches = list_suspicious_processes()
    file_changes = check_file_integrity(MONITORED_FILES)
    return render_template('host.html',
        suspicious_procs=suspicious_procs,
        malware_matches=malware_matches,
        file_changes=file_changes)

# ✅ Log Anomaly Detection
@app.route('/log', methods=['GET', 'POST'])
def log():
    anomalies = None
    report_path = None
    if request.method == 'POST':
        log_file = request.files.get('log_file')
        if log_file:
            path = os.path.join(UPLOAD_FOLDER, log_file.filename)
            log_file.save(path)
            anomalies = detect_log_anomalies(path)
            report_path = os.path.join('static', 'log_report.pdf')
            generate_log_report(anomalies, report_path)
            flash('📝 Log file analyzed and report generated.')
    return render_template('log.html', anomalies=anomalies, report_path=report_path)

# ✅ Phishing / Malicious URL Detection
@app.route('/phishing', methods=['GET', 'POST'])
def phishing():
    result = None
    if request.method == 'POST':
        input_data = request.form.get('input_data')
        if input_data:
            is_malicious = is_phishing(input_data)
            result = '⚠️ This input is likely PHISHING/malicious.' if is_malicious else '✔️ Input appears safe.'
    return render_template('phishing.html', result=result)

# 🔁 Live Packet Monitoring with WebSocket
@socketio.on('start_monitoring')
def start_monitoring(data):
    interface = data['interface']
    thread = threading.Thread(target=monitor_traffic, args=(interface,))
    thread.daemon = True
    thread.start()
    emit('monitor_started', {'msg': f'Started monitoring {interface}'})

def monitor_traffic(interface):
    def handle(pkt):
        if pkt.haslayer(scapy.IP):
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            proto = "TCP" if pkt.haslayer(scapy.TCP) else "Other"
            msg = f"{proto} packet: {src} → {dst}"

            if pkt.haslayer(scapy.TCP):
                flags = pkt[scapy.TCP].flags
                sport = pkt[scapy.TCP].sport
                dport = pkt[scapy.TCP].dport
                msg = f"{proto} {src}:{sport} → {dst}:{dport} | Flags={flags}"
                if flags == 'S':
                    msg = f"⚠️ SYN packet from {src}:{sport} to {dst}:{dport}"

            alert = {"ip": src, "msg": msg}
            socketio.emit('packet_alert', alert)

    scapy.sniff(iface=interface, prn=handle, store=False)

if __name__ == '__main__':
    socketio.run(app, debug=True)
