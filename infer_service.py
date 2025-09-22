import joblib
import time
from logger_util import log_attack
import os
import subprocess

# load models
ISO_MODEL_PATH = 'models/isolation_forest.joblib'
ISO_SCALER_PATH = 'models/iso_scaler.joblib'
RF_MODEL_PATH = 'models/rf_classifier.joblib'
RF_SCALER_PATH = 'models/rf_scaler.joblib'

iso_model = None
iso_scaler = None
rf_model = None
rf_scaler = None

if os.path.exists(ISO_MODEL_PATH):
    iso_model = joblib.load(ISO_MODEL_PATH)
    iso_scaler = joblib.load(ISO_SCALER_PATH)

if os.path.exists(RF_MODEL_PATH):
    rf_model = joblib.load(RF_MODEL_PATH)
    rf_scaler = joblib.load(RF_SCALER_PATH)


def block_ip_linux(ip):
    # WARNING: This modifies iptables. Use in controlled/demo env only.
    try:
        subprocess.run(['sudo','iptables','-I','INPUT','-s', ip, '-j', 'DROP'], check=True)
        return True
    except Exception as e:
        print('block_ip_linux error', e)
        return False


def score_feature(feat):
    """Return decision dict: {'anomaly_score':..., 'is_anomaly':bool, 'supervised_label':None} """
    import numpy as np
    X = [[feat['packets'], feat['bytes'], feat['unique_dst_ports'], feat['duration'], feat['protocol_count']]]
    decision = {'anomaly_score': None, 'is_anomaly': False, 'supervised_label': None}
    if iso_model is not None and iso_scaler is not None:
        Xs = iso_scaler.transform(X)
        score = iso_model.decision_function(Xs)[0]
        # lower score -> more anomalous for sklearn IsolationForest
        is_anom = iso_model.predict(Xs)[0] == -1
        decision['anomaly_score'] = float(score)
        decision['is_anomaly'] = bool(is_anom)
    if rf_model is not None and rf_scaler is not None:
        Xr = rf_scaler.transform(X)
        pred = rf_model.predict_proba(Xr)[0]
        label = rf_model.classes_[pred.argmax()]
        prob = pred.max()
        decision['supervised_label'] = {'label': str(label), 'prob': float(prob)}
    return decision


def handle_feature(feat):
    # decides whether to log and optionally block
    dec = score_feature(feat)
    src = feat['src_ip']
    extra = {'feat': feat, 'dec': dec}

    if dec['is_anomaly']:
        log_attack(src, 'Anomaly', 'Detected', extra=extra)
        # automatic blocking example (use with caution)
        blocked = block_ip_linux(src)
        log_attack(src, 'AutoBlock', 'Success' if blocked else 'Failed', extra={'blocked': blocked})
    elif dec.get('supervised_label') and dec['supervised_label']['prob'] > 0.85:
        lab = dec['supervised_label']['label']
        log_attack(src, lab, 'Detected', extra=extra)
        # For certain labels we may block
        if lab.lower() in ['portscan','ddos']:
            blocked = block_ip_linux(src)
            log_attack(src, 'AutoBlock', 'Success' if blocked else 'Failed', extra={'blocked': blocked})
    else:
        # optional: log low-severity anomalies for auditing
        if dec['anomaly_score'] is not None and dec['anomaly_score'] < -0.1:
            log_attack(src, 'LowConfidenceAnomaly', 'Investigate', extra=extra)


# Example: run consumer loop for features coming from a queue
if __name__ == '__main__':
    import queue
    # For demo you can push features into this queue from data_collector.FEATURE_QUEUE
    demo_q = queue.Queue()
    print('Starting demo infer loop...')
    try:
        while True:
            if not demo_q.empty():
                feat = demo_q.get()
                handle_feature(feat)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('Stopping')
