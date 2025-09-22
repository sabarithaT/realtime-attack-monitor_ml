from collections import defaultdict
import time
import math

class FeatureStore:
    def __init__(self, window_seconds=5):
        self.window_seconds = window_seconds
        self.buckets = defaultdict(lambda: {
            'first_ts': None, 'last_ts': None, 'packets': 0, 'bytes': 0, 'dst_ports': set(), 'protocols': set()
        })
        self.last_emit = time.time()

    def _window_key(self, src_ip, ts):
        win = int(ts // self.window_seconds)
        return (src_ip, win)

    def ingest_packet(self, src_ip, dst_ip, dst_port, proto, size, ts):
        key = self._window_key(src_ip, ts)
        b = self.buckets[key]
        if b['first_ts'] is None:
            b['first_ts'] = ts
        b['last_ts'] = ts
        b['packets'] += 1
        b['bytes'] += size
        if dst_port:
            b['dst_ports'].add(dst_port)
        if proto:
            b['protocols'].add(proto)

    def maybe_emit_features(self):
        now = time.time()
        emitted = []
        if now - self.last_emit < self.window_seconds:
            return []
        # emit all complete windows (older than current)
        cutoff = int(now // self.window_seconds) - 1
        keys_to_remove = []
        for (src_ip, win), data in list(self.buckets.items()):
            if win <= cutoff:
                duration = (data['last_ts'] - data['first_ts']) if (data['first_ts'] and data['last_ts']) else 0.0
                feat = {
                    'window_start': win * self.window_seconds,
                    'src_ip': src_ip,
                    'packets': data['packets'],
                    'bytes': data['bytes'],
                    'unique_dst_ports': len(data['dst_ports']),
                    'duration': duration,
                    'protocol_count': len(data['protocols'])
                }
                emitted.append(feat)
                keys_to_remove.append((src_ip, win))
        for k in keys_to_remove:
            del self.buckets[k]
        self.last_emit = now
        return emitted
