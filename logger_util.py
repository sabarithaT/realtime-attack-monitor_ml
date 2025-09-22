integrates with your existing logs.json)
# logger_util.py

import json
import os
from datetime import datetime

LOG_FILE = 'logs.json'


def log_attack(user_id, attack_type, status, extra=None):
    entry = {
        'user_id': user_id,
        'attack': attack_type,
        'status': status,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'extra': extra or {}
    }
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        except Exception:
            logs = []
    logs.append(entry)
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=2)
    print('[LOG]', entry)
    return entry
