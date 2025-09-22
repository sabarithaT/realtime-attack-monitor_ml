import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib


def load_feature_csv(path):
    return pd.read_csv(path)


def prepare_X(df):
    X = df[['packets','bytes','unique_dst_ports','duration','protocol_count']].fillna(0)
    return X


def train_unsupervised(X):
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    iso = IsolationForest(n_estimators=200, contamination=0.01, random_state=42)
    iso.fit(Xs)
    return iso, scaler


def train_supervised(X, y):
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    clf = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)
    clf.fit(Xs, y)
    return clf, scaler


if __name__ == '__main__':
    # Example: you should create a CSV of features (see README) from labeled data or simulated attacks
    df = load_feature_csv('training_features.csv')

    X = prepare_X(df)

    # Unsupervised baseline training (train on normal subset)
    if 'label' in df.columns:
        normal_df = df[df['label'] == 'normal']
    else:
        normal_df = df

    iso, iso_scaler = train_unsupervised(prepare_X(normal_df))
    joblib.dump(iso, 'models/isolation_forest.joblib')
    joblib.dump(iso_scaler, 'models/iso_scaler.joblib')
    print('Saved IsolationForest and scaler')

    # If labels available, train supervised classifier
    if 'label' in df.columns:
        X_all = prepare_X(df)
        y = df['label']
        clf, clf_scaler = train_supervised(X_all, y)
        joblib.dump(clf, 'models/rf_classifier.joblib')
        joblib.dump(clf_scaler, 'models/rf_scaler.joblib')
        print('Saved RandomForest and scaler')
