import time
import threading
import queue
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

from feature_store import FeatureStore

FEATURE_QUEUE = queue.Queue()
store = FeatureStore(window_seconds=5)


def packet_callback(pkt):
    """Called by scapy for every captured packet."""
    try:
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt.proto
        sport = pkt.sport if hasattr(pkt, 'sport') else None
        dport = pkt.dport if hasattr(pkt, 'dport') else None
        size = len(pkt)
        ts = datetime.now().timestamp()

        store.ingest_packet(src_ip=src, dst_ip=dst, dst_port=dport, proto=proto, size=size, ts=ts)

        # periodically flush aggregated features into queue
        features = store.maybe_emit_features()
        if features:
            for f in features:
                FEATURE_QUEUE.put(f)

    except Exception as e:
        print('packet_callback error', e)


def start_sniffer(interface=None):
    print('Starting sniffer... (ctrl-c to stop)')
    sniff(prn=packet_callback, store=False, iface=interface, filter="ip")


if __name__ == '__main__':
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()

    # simple consumer loop to print features
    try:
        while True:
            while not FEATURE_QUEUE.empty():
                f = FEATURE_QUEUE.get()
                print('EMIT_FEATURE:', f)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('Stopping')
