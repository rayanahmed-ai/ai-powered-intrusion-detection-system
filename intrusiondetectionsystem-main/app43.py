# cinematic_siem_final_fixed.py
"""
Cinematic SIEM Pro - Full Working Version
Features:
- IsolationForest anomaly detection
- Surrogate RandomForest for XAI
- SHAP global & local explanations
- DiCE counterfactuals
- Pentest simulation & batch alerts
- Adversarial robustness test
- SQLite alert storage with severity
"""

import streamlit as st
import pandas as pd
import numpy as np
import sqlite3, os, time, joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
import matplotlib.pyplot as plt

# Optional heavy libs
try:
    import shap
    SHAP_AVAILABLE = True
except Exception:
    SHAP_AVAILABLE = False

try:
    import dice_ml
    DICE_AVAILABLE = True
except Exception:
    DICE_AVAILABLE = False

try:
    import pyttsx3
    VOICE_AVAILABLE = True
except Exception:
    VOICE_AVAILABLE = False

# ----------------------------
# Config / DB / Model paths
# ----------------------------
st.set_page_config(page_title="Cinematic SIEM Pro", layout="wide")
BASE_DIR = os.path.dirname(__file__) if '__file__' in globals() else os.getcwd()
MODEL_DIR = os.path.join(BASE_DIR, "models_cinematic")
os.makedirs(MODEL_DIR, exist_ok=True)
DB_PATH = os.path.join(BASE_DIR, "siem_alerts.db")

# SQLite connection
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    alert_type TEXT,
    details TEXT,
    severity TEXT
)
""")
conn.commit()

def insert_alert(alert_type, details, severity="medium"):
    ts = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO alerts (ts, alert_type, details, severity) VALUES (?,?,?,?)",
                (ts, alert_type, details, severity))
    conn.commit()
    if VOICE_AVAILABLE:
        try:
            engine = pyttsx3.init()
            engine.say(f"Alert: {alert_type}")
            engine.runAndWait()
        except Exception:
            pass

# ----------------------------
# Helpers
# ----------------------------
def safe_read_csv(uploaded):
    try:
        return pd.read_csv(uploaded)
    except Exception as e:
        st.error(f"Failed reading CSV: {e}")
        return None

def ensure_columns(df, expected):
    for c in expected:
        if c not in df.columns:
            if c in ("src_ip","dst_ip","protocol"):
                df[c] = "missing"
            else:
                df[c] = 0
    return df

def featurize(df):
    d = df.copy()
    expected = ['failed_logins','sudo_cmds','service_restarts','cron_jobs',
                'iface_up','dhcp_events','wifi_connections','src_ip','dst_ip','protocol','is_syn']
    d = ensure_columns(d, expected)
    le_ip = LabelEncoder()
    try:
        d['src_ip_enc'] = le_ip.fit_transform(d['src_ip'].astype(str))
        d['dst_ip_enc'] = le_ip.fit_transform(d['dst_ip'].astype(str))
    except Exception:
        d['src_ip_enc'] = d['src_ip'].astype(str).apply(lambda x: abs(hash(x)) % 100000)
        d['dst_ip_enc'] = d['dst_ip'].astype(str).apply(lambda x: abs(hash(x)) % 100000)
    d['proto_enc'] = d['protocol'].astype(str).apply(lambda x: abs(hash(x)) % 100000)
    numeric_cols = ['failed_logins','sudo_cmds','service_restarts','cron_jobs',
                    'iface_up','dhcp_events','wifi_connections','src_ip_enc','dst_ip_enc','proto_enc','is_syn']
    X = d[numeric_cols].fillna(0).astype(float)
    return X, numeric_cols

def train_or_load_iso(X, contamination=0.02):
    iso_path = os.path.join(MODEL_DIR, "isoforest.joblib")
    scaler_path = os.path.join(MODEL_DIR, "scaler.joblib")
    if os.path.exists(iso_path) and os.path.exists(scaler_path):
        try:
            iso = joblib.load(iso_path)
            scaler = joblib.load(scaler_path)
            return iso, scaler
        except Exception:
            pass
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    iso = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    iso.fit(Xs)
    joblib.dump(iso, iso_path)
    joblib.dump(scaler, scaler_path)
    return iso, scaler

def train_surrogate(X, iso, scaler):
    sur_path = os.path.join(MODEL_DIR, "surrogate.joblib")
    if os.path.exists(sur_path):
        try:
            return joblib.load(sur_path)
        except Exception:
            pass
    Xs = scaler.transform(X)
    iso_preds = iso.predict(Xs)
    y = (iso_preds == -1).astype(int)
    if len(np.unique(y)) < 2:
        return None
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X, y)
    joblib.dump(clf, sur_path)
    return clf

def adversarial_test(iso, scaler, X, eps_frac=0.08):
    Xs = scaler.transform(X)
    std = Xs.std(axis=0)
    eps = std * eps_frac
    Xp = Xs + np.random.normal(0, eps, Xs.shape)
    y1 = iso.predict(Xs)
    y2 = iso.predict(Xp)
    flips = np.sum(y1 != y2)
    return flips, len(y1), float(flips)/max(1,len(y1))

# ----------------------------
# Streamlit UI
# ----------------------------
st.title("🎬 Cinematic SIEM Pro — Full Working Version")

# Sidebar
st.sidebar.header("Controls")
contamination = st.sidebar.slider("IsolationForest contamination", 0.001, 0.2, 0.02, 0.001)
adv_eps = st.sidebar.slider("Adversarial epsilon fraction", 0.0, 0.5, 0.08, 0.01)
batch_size = st.sidebar.number_input("Pentest batch size", 1, 100, 10)
batch_threshold = st.sidebar.number_input("Pentest anomaly threshold per batch", 1, 10, 3)

# Upload
st.header("1) Upload CSV Dataset")
uploaded = st.file_uploader("Upload log CSV", type=['csv'])
if uploaded:
    df = safe_read_csv(uploaded)
    if df is None: st.stop()
    st.subheader("Preview")
    st.dataframe(df.head(10))

    X, numeric_cols = featurize(df)
    st.write("Features used:", numeric_cols)

    # Train/load IsolationForest
    iso, scaler = train_or_load_iso(X, contamination)
    Xs = scaler.transform(X)
    iso_scores = -iso.decision_function(Xs)
    q = st.slider("Anomaly quantile", 90, 99, 95)
    thresh = np.percentile(iso_scores, q)
    is_anom = (iso_scores >= thresh).astype(int)
    df_results = df.copy()
    df_results['iso_score'] = iso_scores
    df_results['anomaly_if'] = is_anom
    st.write(f"Detected anomalies (IsolationForest) with quantile {q}% → threshold {thresh:.4f}")
    st.dataframe(df_results[df_results['anomaly_if']==1].head(200))

    # Save alerts
    for idx, row in df_results[df_results['anomaly_if']==1].head(200).iterrows():
        insert_alert("IsolationForest anomaly", f"Row {idx} iso_score={row['iso_score']:.4f}", "high")

    # Surrogate
    surrogate = train_surrogate(X, iso, scaler)
    if surrogate is None:
        st.warning("Surrogate classifier could not be trained (likely one-class). XAI limited.")
    else:
        st.success("Surrogate classifier trained for SHAP & DiCE.")

    # Ensemble
    ensemble_score = iso_scores.copy()
    if surrogate:
        proba = surrogate.predict_proba(X)[:,1]
        iso_norm = (ensemble_score - ensemble_score.min())/(ensemble_score.max()-ensemble_score.min()+1e-9)
        ens = 0.6*iso_norm + 0.4*proba
        df_results['ensemble'] = ens
    else:
        df_results['ensemble'] = ensemble_score
    st.header("Top anomalies by ensemble")
    top_k = st.number_input("Show top K anomalies", 1, 500, 20)
    st.dataframe(df_results.sort_values('ensemble', ascending=False).head(top_k))

    # Save models
    if st.button("Save models"):
        joblib.dump(iso, os.path.join(MODEL_DIR,"isoforest.joblib"))
        joblib.dump(scaler, os.path.join(MODEL_DIR,"scaler.joblib"))
        if surrogate: joblib.dump(surrogate, os.path.join(MODEL_DIR,"surrogate.joblib"))
        st.success("Models saved.")

    # ---------------------------- SHAP
    st.header("SHAP Explainability")
    if surrogate and SHAP_AVAILABLE:
        try:
            X_np = X.to_numpy()
            explainer = shap.TreeExplainer(surrogate)
            shap_vals = explainer.shap_values(X_np)
            shap_anom = shap_vals[1]
            st.write("Global feature importance")
            shap.summary_plot(shap_anom, X_np, feature_names=X.columns, show=False)
            st.pyplot(plt.gcf())
            plt.clf()
            idx_local = st.number_input("Local SHAP index", 0, len(X)-1, 0)
            shap.force_plot(explainer.expected_value[1],
                            shap_anom[idx_local,:],
                            X_np[idx_local,:],
                            matplotlib=True, show=False)
            st.pyplot(plt.gcf())
            plt.clf()
        except Exception as e:
            st.warning(f"SHAP failed: {e}")
    else:
        st.info("SHAP not available or surrogate missing.")

    # ---------------------------- DiCE counterfactuals
    st.header("DiCE Counterfactuals")
    if DICE_AVAILABLE and surrogate:
        try:
            df_cf = X.copy()
            df_cf['target'] = (iso.predict(scaler.transform(X))==-1).astype(int)
            dice_data = dice_ml.Data(dataframe=df_cf, outcome_name='target', continuous_features=numeric_cols)
            dice_model = dice_ml.Model(model=surrogate, backend="sklearn")
            dice_exp = dice_ml.Dice(dice_data, dice_model)
            anomaly_idx = df_cf[df_cf['target']==1].index
            if len(anomaly_idx)>0:
                cf = dice_exp.generate_counterfactuals(df_cf.iloc[[anomaly_idx[0]]],
                                                       total_CFs=1,
                                                       desired_class="opposite")
                st.write("Counterfactual(s):")
                st.dataframe(cf.cf_examples_list[0].final_cfs_df)
            else:
                st.info("No anomalous row to generate counterfactuals.")
        except Exception as e:
            st.warning(f"DiCE failed: {e}")
    else:
        st.info("DiCE not available or surrogate missing.")

    # ---------------------------- Adversarial test
    st.header("Adversarial Robustness Test")
    flips, total, frac = adversarial_test(iso, scaler, X, eps_frac=adv_eps)
    st.write(f"Label flips: {flips}/{total} ({frac*100:.2f}%)")
    frag_threshold = st.slider("Alert fragility threshold", 0.0, 1.0, 0.10, 0.01)
    if frac >= frag_threshold:
        insert_alert("Adversarial fragility detected", f"{frac*100:.2f}% flips", "critical")
        st.error("Adversarial fragility exceeded threshold — alert created.")

    # ---------------------------- Pentest
    st.header("Pentest Simulator")
    payload = st.selectbox("Payload", ["SQLi","XSS","Directory Traversal","Brute Force"])
    target_ip = st.text_input("Target IP", "10.0.2.15")
    attempts = st.number_input("Attempts", 1, 500, 50)
    if st.button("Run Pentest Simulation"):
        batch_count = 0
        batch_anoms = 0
        total_inserted = 0
        for i in range(int(attempts)):
            if payload=="SQLi": msg=f"SELECT * FROM users WHERE id={i} OR 1=1"
            elif payload=="XSS": msg=f"<script>alert('xss {i}')</script>"
            elif payload=="Directory Traversal": msg="../"*(i%5)+"etc/passwd"
            else: msg=f"login_attempt_{i}"
            src = f"10.0.0.{(i%240)+2}"; dst = target_ip
            row = {'failed_logins':0,'sudo_cmds':0,'service_restarts':0,'cron_jobs':0,
                   'iface_up':0,'dhcp_events':0,'wifi_connections':0,
                   'src_ip':src,'dst_ip':dst,'protocol':'TCP','is_syn':0}
            Xrow,_ = featurize(pd.DataFrame([row]))
            Xrow_s = scaler.transform(Xrow)
            pred = iso.predict(Xrow_s)[0]
            if pred==-1:
                insert_alert("Pentest anomaly", f"{payload} from {src} to {dst} attempt {i}", "high")
                batch_anoms += 1
            batch_count += 1; total_inserted += 1
            if batch_count>=batch_size:
                if batch_anoms>=batch_threshold:
                    insert_alert("Pentest batch alert", f"{batch_anoms}/{batch_size} anomalies", "critical")
                batch_count = batch_anoms = 0
            time.sleep(0.005)
        st.success(f"Pentest finished; {total_inserted} attempts injected.")

    # ---------------------------- Alerts viewer
    st.header("Alerts")
    alerts_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 500", conn)
    if not alerts_df.empty:
        st.dataframe(alerts_df)
    else:
        st.info("No alerts yet.")

else:
    st.info("Upload dataset CSV to begin. Example header: failed_logins,sudo_cmds,service_restarts,cron_jobs,iface_up,dhcp_events,wifi_connections,src_ip,dst_ip,protocol,is_syn")
