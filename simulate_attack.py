# simulate_attack.py
"""
Safe test harness: simulates feature payloads and calls your detection's handle_feature()
This DOES NOT send network traffic. It only invokes your Python detection logic locally.
Run in the project root where your detection module (the file containing handle_feature) is accessible.
"""

import time
import importlib
import sys

# List of likely module names where handle_feature() is defined.
# If your file has another name, add it here. e.g. 'my_detector'
CANDIDATE_MODULES = [
    'detection', 'detector', 'inference', 'realtime_detector', 'main', 'app', 'server'
]

det_mod = None
for name in CANDIDATE_MODULES:
    try:
        det_mod = importlib.import_module(name)
        if hasattr(det_mod, 'handle_feature'):
            print(f"[OK] imported handle_feature from module '{name}'")
            break
    except Exception:
        continue

if det_mod is None or not hasattr(det_mod, 'handle_feature'):
    print("ERROR: couldn't find a module with handle_feature().")
    print("Please update CANDIDATE_MODULES list with the filename (without .py) that contains handle_feature().")
    sys.exit(1)

handle_feature = det_mod.handle_feature

# Example simulated features:
SIMULATED_FEATURES = [
    # Normal traffic
    {
        'src_ip': '192.168.1.10',
        'packets': 5,
        'bytes': 2500,
        'unique_dst_ports': 2,
        'duration': 4.5,
        'protocol_count': 1
    },
    # Low-confidence anomaly (slightly suspicious)
    {
        'src_ip': '192.168.1.20',
        'packets': 40,
        'bytes': 15000,
        'unique_dst_ports': 4,
        'duration': 8.0,
        'protocol_count': 1
    },
    # Portscan-like: many unique destination ports in short window
    {
        'src_ip': '10.0.0.5',
        'packets': 120,
        'bytes': 40000,
        'unique_dst_ports': 60,
        'duration': 2.0,
        'protocol_count': 1
    },
    # DDoS-like: huge packet count, steady single port
    {
        'src_ip': '203.0.113.45',
        'packets': 5000,
        'bytes': 1500000,
        'unique_dst_ports': 1,
        'duration': 10.0,
        'protocol_count': 1
    }
]

print("Starting simulation. Each feature will be sent to handle_feature() with a short delay.")
for i, feat in enumerate(SIMULATED_FEATURES, 1):
    print(f"\n--- Simulated payload #{i} --> {feat['src_ip']} ---")
    try:
        handle_feature(feat)
    except Exception as e:
        print("Exception when calling handle_feature():", e)
        print("Make sure your detection module loads models and logger_util properly.")
    time.sleep(2)  # wait between simulated events

print("\nSimulation finished. Check logs.json and the dashboard for results.")
