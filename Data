import os
from google.colab import files

# Create the 'data' directory your code expects
os.makedirs('/content/data', exist_ok=True)

# Open the file picker
print("Please select your CIC-IDS2018 CSV files...")
uploaded = files.upload()

# Move the uploaded files into the data folder
for filename in uploaded.keys():
    os.rename(filename, f'/content/data/{filename}')

print(f"Done! Files are now in /content/data/: {os.listdir('/content/data')}")


# ============================================================
#  SOVEREIGN DEFENDER — CIC-IDS2018 — Notebook Edition
#  Paste this entire cell into Colab / Jupyter and run.
# ============================================================

# ---------- 0) Install dependencies (Colab only) ----------
# !pip install -q xgboost shap joblib

import os, json, time, uuid, glob
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

# ---------- 1) Config ----------
BASE_DIR     = Path(os.getcwd()).resolve()
DATA_DIR     = BASE_DIR / "data"
ARTIFACT_DIR = BASE_DIR / "artifacts"
REPORT_DIR   = BASE_DIR / "reports"
for d in (ARTIFACT_DIR, REPORT_DIR):
    d.mkdir(exist_ok=True)

print(f"[config] BASE_DIR = {BASE_DIR}")
print(f"[config] DATA_DIR = {DATA_DIR}  (exists: {DATA_DIR.exists()})")

CSV_GLOB        = "*.csv"
RANDOM_STATE    = 42
TEST_SIZE       = 0.30
CONTAMINATION   = 0.05
N_ESTIMATORS    = 200

RISK_THRESHOLDS = {"low": 40, "medium": 65, "high": 85, "critical": 100}
CONFIDENCE_FLOOR = 0.85

FEATURE_COLS = [
    "Dst Port", "Protocol", "Flow Duration",
    "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Mean", "Bwd Pkt Len Mean",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std",
    "Fwd IAT Mean", "Bwd IAT Mean",
    "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std",
    "SYN Flag Cnt", "ACK Flag Cnt", "PSH Flag Cnt", "URG Flag Cnt",
    "Down/Up Ratio", "Init Fwd Win Byts", "Init Bwd Win Byts",
]
LABEL_COL    = "Label"
BENIGN_LABEL = "Benign"

# ---------- 2) Data loader ----------
def load_all_csvs():
    files = sorted(Path(DATA_DIR).glob(CSV_GLOB))
    if not files:
        raise FileNotFoundError(
            f"No CSVs found in {DATA_DIR}. "
            "Upload CIC-IDS2018 *.csv files there."
        )
    frames = []
    for f in files:
        print(f"[load] {f.name}")
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df["__source_file"] = f.name
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    print(f"[load] Combined shape: {full.shape}")
    return full

# ---------- 3) Preprocess ----------
def clean(df):
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    df.replace([np.inf, -np.inf, "Infinity", "-Infinity"], np.nan, inplace=True)
    df.dropna(subset=[LABEL_COL], inplace=True)
    df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()

    before = len(df)
    df.drop_duplicates(inplace=True)
    print(f"[clean] Dropped {before - len(df):,} duplicates")

    keep = [c for c in FEATURE_COLS if c in df.columns] + [LABEL_COL, "__source_file"]
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"[clean] WARNING missing: {missing}")
    df = df[keep].copy()

    num_cols = [c for c in df.columns if c not in (LABEL_COL, "__source_file")]
    df[num_cols] = df[num_cols].fillna(df[num_cols].median())
    for c in num_cols:
        lo, hi = df[c].quantile([0.01, 0.99])
        df[c] = df[c].clip(lo, hi)

    print(f"[clean] Shape: {df.shape}")
    return df

def temporal_split(df, test_size):
    train_parts, test_parts = [], []
    for src, g in df.groupby("__source_file", sort=False):
        g = g.reset_index(drop=True)
        cut = int(len(g) * (1 - test_size))
        train_parts.append(g.iloc[:cut])
        test_parts.append(g.iloc[cut:])
    train = pd.concat(train_parts, ignore_index=True)
    test  = pd.concat(test_parts,  ignore_index=True)
    print(f"[split] Train={len(train):,}  Test={len(test):,}")
    return train, test

# ---------- 4) Baseline ----------
class BaselineStore:
    def __init__(self):
        self.mean = self.std = self.quantiles = None
    def fit(self, Xb):
        self.mean = Xb.mean(axis=0)
        self.std  = Xb.std(axis=0) + 1e-9
        self.quantiles = np.percentile(Xb, [5,25,50,75,95], axis=0)
        return self
    def zscore(self, X):
        return np.abs((X - self.mean) / self.std)

# ---------- 5) Detector ----------
class IsolationForestDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
    def fit(self, Xb):
        self.model.fit(Xb); return self
    def score(self, X):
        raw = -self.model.score_samples(X)
        return 1 / (1 + np.exp(-(raw - raw.mean()) / (raw.std() + 1e-9)))

# ---------- 6) Risk engine ----------
class RiskEngine:
    def __init__(self, baseline, detector, feature_names):
        self.baseline = baseline
        self.detector = detector
        self.feature_names = feature_names
    def score_batch(self, X_raw, X_scaled):
        anomaly = self.detector.score(X_scaled)
        z       = self.baseline.zscore(X_scaled)
        z_mean  = z.mean(axis=1)
        z_max   = z.max(axis=1)
        risk = (0.55*anomaly*100
              + 0.30*np.clip(z_mean/3, 0, 1)*100
              + 0.15*np.clip(z_max/5,  0, 1)*100)
        risk = np.clip(risk, 0, 100)
        confidence = np.clip(0.5*anomaly + 0.5*np.clip(z_mean/3, 0, 1), 0, 1)
        top_factors = []
        for i in range(len(X_raw)):
            contrib = z[i] * np.abs(X_scaled[i])
            idx = np.argsort(contrib)[::-1][:3]
            top_factors.append([(self.feature_names[j], float(contrib[j]))
                                for j in idx])
        return pd.DataFrame({
            "risk": risk, "confidence": confidence,
            "anomaly": anomaly, "baseline_z": z_mean,
            "top_factors": top_factors,
        })

# ---------- 7) Decision ----------
def decide(risk, conf):
    if risk >= RISK_THRESHOLDS["high"] and conf >= CONFIDENCE_FLOOR:
        return "CRITICAL"
    if risk >= RISK_THRESHOLDS["medium"]:
        return "HIGH"
    if risk >= RISK_THRESHOLDS["low"]:
        return "MEDIUM"
    return "LOW"

ACTION_TABLE = {
    "LOW":      "Allow + log",
    "MEDIUM":   " Enhanced monitoring",
    "HIGH":     " Temporary restriction",
    "CRITICAL": " Full block + freeze",
}

# ---------- 8) Report ----------
def build_and_save_report(row, raw_features):
    incident_id = f"INC-{datetime.utcnow():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"
    report = {
        "incident_id":   incident_id,
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "level":         row["level"],
        "risk_score":    round(float(row["risk"]), 2),
        "confidence":    round(float(row["confidence"]), 3),
        "top_factors":   [{"feature": f, "contribution": round(c,3)}
                          for f, c in row["top_factors"]],
        "raw_features":  {k: float(v) for k, v in raw_features.items()},
    }
    txt = REPORT_DIR / f"{incident_id}.txt"
    js  = REPORT_DIR / f"{incident_id}.json"
    txt.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    js.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return txt, report



def banner(t):
    print("\n" + "="*62 + f"\n  {t}\n" + "="*62)

banner("1. Load CIC-IDS2018")
df = load_all_csvs()
print(df[LABEL_COL].value_counts().head(20))

banner("2. Clean + split")
df = clean(df)
train, test = temporal_split(df, TEST_SIZE)

cols    = [c for c in FEATURE_COLS if c in train.columns]
scaler  = StandardScaler().fit(train[cols])
X_tr    = scaler.transform(train[cols])
X_te_raw= test[cols].values
X_te    = scaler.transform(X_te_raw)
y_te    = (test[LABEL_COL] != BENIGN_LABEL).astype(int).values
print(f"[main] {len(cols)} features used")

banner("3. Baseline on benign-only")
mask = (train[LABEL_COL] == BENIGN_LABEL).values
baseline = BaselineStore().fit(X_tr[mask])
print(f"[main] Benign rows: {mask.sum():,}")

banner("4. Isolation Forest")
det = IsolationForestDetector().fit(X_tr[mask])

banner("5. Score + decide")
t0 = time.time()
engine = RiskEngine(baseline, det, cols)
scores = engine.score_batch(X_te_raw, X_te)
scores["level"] = [decide(r, c)
                   for r, c in zip(scores["risk"], scores["confidence"])]
print(f"[main] Scored {len(scores):,} in {time.time()-t0:.1f}s")

banner("6. Evaluation")
pred = (scores["level"] != "LOW").astype(int).values
print(classification_report(y_te, pred,
        target_names=["Benign","Attack"], digits=3, zero_division=0))
print(confusion_matrix(y_te, pred))
print("\nDecision distribution:")
print(scores["level"].value_counts().to_string())

banner("7. Top-5 incident reports")
top_idx = scores["risk"].sort_values(ascending=False).head(5).index
for i in top_idx:
    row = scores.loc[i]
    raw = dict(zip(cols, X_te_raw[i]))
    path, rep = build_and_save_report(row, raw)
    print(f"  {rep['incident_id']}  risk={rep['risk_score']:>5}  "
          f"conf={rep['confidence']}  →  {ACTION_TABLE[rep['level']]}")

banner("Done")
print("Reports in:", REPORT_DIR)
