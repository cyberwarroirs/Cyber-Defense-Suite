import psutil
import hashlib
import os
import json

# Optional: Load local known malware hashes
MALWARE_HASHES_FILE = 'host_monitoring/malware_hashes.json'
if os.path.exists(MALWARE_HASHES_FILE):
    with open(MALWARE_HASHES_FILE) as f:
        KNOWN_MALWARE_HASHES = set(json.load(f))
else:
    KNOWN_MALWARE_HASHES = set()

def file_hash(filepath):
    """Return SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def list_suspicious_processes():
    """
    Detect suspicious processes:
    - No command line
    - Suspicious names
    - Executing from unusual directories
    - Hash matches malware
    """
    suspicious = []
    malware_matches = []

    suspicious_names = ['svchost.exe', 'cmd.exe', 'powershell.exe', 'python', 'update.exe']
    suspicious_dirs = ['/tmp', '/dev/shm', 'C:\\Temp', 'C:\\Users\\Public']

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = proc.info['name'] or ''
            cmd = proc.info['cmdline'] or []
            exe = proc.info['exe'] or ''

            is_suspicious = False
            if not cmd:
                is_suspicious = True
            if any(name.lower() == bad.lower() for bad in suspicious_names):
                is_suspicious = True
            if any(exe.startswith(path) for path in suspicious_dirs):
                is_suspicious = True

            proc_data = {
                'pid': proc.pid,
                'name': name,
                'cmdline': ' '.join(cmd),
                'exe': exe
            }

            if is_suspicious:
                suspicious.append(proc_data)

            # Malware hash match
            if exe and os.path.exists(exe):
                h = file_hash(exe)
                if h in KNOWN_MALWARE_HASHES:
                    malware_matches.append({**proc_data, 'hash': h})

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return suspicious, malware_matches

def check_file_integrity(monitored_files):
    """
    Check file hashes and return modified or missing files.
    Format: {path: (expected_hash, current_hash or None)}
    """
    changes = {}
    for path, known_hash in monitored_files.items():
        if os.path.exists(path):
            current_hash = file_hash(path)
            if current_hash != known_hash:
                changes[path] = (known_hash, current_hash)
        else:
            changes[path] = (known_hash, None)
    return changes
