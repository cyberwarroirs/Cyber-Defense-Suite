import re
import datetime
import statistics
from collections import Counter

def parse_logs_generic(filepath):
    """
    Generic log parser - tries to extract timestamp, service, and message using flexible regex.
    Falls back gracefully if parsing fails.
    """
    logs = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            # Example regex for common syslog format: "May 29 14:01:23 hostname service: message"
            match = re.match(r'^(\w{3}\s+\d+\s[\d:]+)\s+([\w\-.]+)\s+([\w\-.\/]+)(?:\[\d+\])?:\s+(.*)', line)
            if match:
                time_str, host, service, message = match.groups()
                try:
                    timestamp = datetime.datetime.strptime(time_str, '%b %d %H:%M:%S')
                    # Use current year to complete datetime (logs usually omit year)
                    timestamp = timestamp.replace(year=datetime.datetime.now().year)
                except Exception:
                    timestamp = None
                logs.append({
                    "timestamp": timestamp,
                    "host": host,
                    "service": service,
                    "message": message.strip()
                })
            else:
                # If line doesn't match, log it as unknown type with raw line as message
                logs.append({
                    "timestamp": None,
                    "host": None,
                    "service": "unknown",
                    "message": line.strip()
                })
    return logs

def detect_log_anomalies(filepath):
    logs = parse_logs_generic(filepath)
    alerts = []

    # Filter out logs with missing service
    valid_logs = [log for log in logs if log['service'] and log['service'] != 'unknown']

    # Rule-based detection (extend as needed)
    for log in valid_logs:
        msg = log['message'].lower()
        if 'failed password' in msg or 'authentication failure' in msg:
            alerts.append({**log, "severity": 90, "type": "Rule-Based", "description": "Failed login attempt"})
        elif 'sudo' in msg and 'not in sudoers' in msg:
            alerts.append({**log, "severity": 95, "type": "Rule-Based", "description": "Unauthorized sudo attempt"})
        elif 'error' in msg or 'fail' in msg or 'denied' in msg:
            alerts.append({**log, "severity": 70, "type": "Rule-Based", "description": "Error or failure detected"})

    # Statistical anomaly detection on service log counts
    service_counts = Counter(log['service'] for log in valid_logs)

    if len(service_counts) > 0:
        mean = statistics.mean(service_counts.values())
        std = statistics.stdev(service_counts.values()) if len(service_counts) > 1 else 0

        for service, count in service_counts.items():
            if std > 0 and abs(count - mean) > 2 * std:
                alerts.append({
                    "timestamp": None,
                    "host": None,
                    "service": service,
                    "message": f"{count} log entries detected",
                    "severity": 80,
                    "type": "Statistical",
                    "description": "Spike in log volume for this service"
                })

    return sorted(alerts, key=lambda x: x['severity'], reverse=True)
