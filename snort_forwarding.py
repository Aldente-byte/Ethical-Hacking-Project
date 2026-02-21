#!/usr/bin/env python3
"""
Snort Alert Forwarder with Heartbeat
Tails Snort alert file and sends alerts to remote Flask app via HTTP
Sends periodic heartbeat to indicate forwarder is still running
"""
import time
import requests
import os
import sys
import threading

ALERT_FILE = '/var/log/snort/alert_fast.txt'
FLASK_SERVER = 'http://10.41.153.170:5000'  # Your Windows Flask app
ENDPOINT = '/api/snort-alert'
HEARTBEAT_INTERVAL = 10  # Send heartbeat every 10 seconds

# Add this at the top of snort_forwarder.py
IGNORED_SIDS = {
    '1:1000010',
    '119:228',   # http_inspect - your own Flask traffic
    '116:408',   # ipv4 current net source  
    '116:444',   # ipv4 option set
    '129:3',     # stream_tcp data on closed stream
    '129:16',    # stream_tcp FIN issue
    '112:1',     # arp_spoof (noisy background)
    '1:1000020', # ICMP packets (background IPv6)
}

def should_send(alert_line):
    for sid in IGNORED_SIDS:
        if f'[{sid}:' in alert_line or f'[{sid}]' in alert_line:
            return False
    return True

def tail_file(filename):
    """Tail a file like 'tail -f'"""
    with open(filename, 'r') as f:
        # Go to end of file
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)

def send_alert(alert_line):
    """Send alert to Flask server"""
    try:
        response = requests.post(
            f"{FLASK_SERVER}{ENDPOINT}",
            json={'alert_line': alert_line},
            timeout=2
        )
        if response.status_code == 200:
            print(f"✓ Sent alert: {alert_line[:80]}")
        else:
            print(f"✗ Error {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Connection error: {e}")

def send_heartbeat():
    """Send heartbeat ping to Flask server"""
    while True:
        try:
            response = requests.post(
                f"{FLASK_SERVER}{ENDPOINT}",
                json={'heartbeat': True},
                timeout=2
            )
            if response.status_code == 200:
                print(f"Heartbeat sent")
            else:
                print(f"✗ Heartbeat failed: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"✗ Heartbeat connection error: {e}")
        
        time.sleep(HEARTBEAT_INTERVAL)

def main():
    print(f"[Snort Forwarder] Starting with heartbeat...")
    print(f"  Monitoring: {ALERT_FILE}")
    print(f"  Sending to: {FLASK_SERVER}{ENDPOINT}")
    print(f"  Heartbeat interval: {HEARTBEAT_INTERVAL}s")
    
    if not os.path.exists(ALERT_FILE):
        print(f"ERROR: Alert file not found: {ALERT_FILE}")
        sys.exit(1)
    
    # Start heartbeat thread
    heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
    heartbeat_thread.start()
    print("[Snort Forwarder] Heartbeat thread started")
    
    print("[Snort Forwarder] Waiting for alerts...\n")
    
    try:
        for alert_line in tail_file(ALERT_FILE):
            if alert_line and '[**]' in alert_line and should_send(alert_line):
                send_alert(alert_line)
    except KeyboardInterrupt:
        print("\n[Snort Forwarder] Stopped")

if __name__ == '__main__':
    main()
