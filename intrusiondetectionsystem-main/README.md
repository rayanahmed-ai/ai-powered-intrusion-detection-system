🎬 Cinematic SIEM Pro

Explainable Anomaly-Based Intrusion Detection System

📌 Overview

Cinematic SIEM Pro is an anomaly-based Intrusion Detection System (IDS) integrated into a SIEM-style security analytics platform. The system analyzes security log data to detect suspicious or malicious behavior using unsupervised machine learning, while providing explainability, robustness evaluation, and alert management.

The project emphasizes practical AI for cybersecurity, combining detection, explanation, and adversarial evaluation in a single interactive application.

🛡️ System Classification

Type: Anomaly-Based Intrusion Detection System (IDS)

Architecture: IDS + Lightweight SIEM Hybrid

Detection Method: Unsupervised ML (Isolation Forest)

Focus: Explainability, robustness, and applied security analytics

⚙️ Core Features
🔍 Anomaly Detection

Uses Isolation Forest to detect deviations from normal system and network behavior

Operates on security-relevant log features such as:

Failed login attempts

Privileged command usage

Service restarts and cron activity

Network indicators (IP addresses, protocol, SYN flag)

🧠 Explainable AI (XAI)

Trains a surrogate Random Forest classifier to approximate anomaly decisions

Provides:

Global explanations using SHAP feature importance

Local explanations for individual anomalous events

Generates counterfactual explanations using DiCE to show how an event could become non-anomalous

🧪 Adversarial Robustness Evaluation

Performs adversarial noise injection on input features

Measures label flip rate under perturbations

Raises alerts when model fragility exceeds a configurable threshold

🚨 Alerting & SIEM Functionality

Stores alerts in SQLite with timestamps and severity levels

Supports:

High-risk anomaly alerts

Batch-based pentest alerts

Critical alerts for adversarial fragility

Includes optional voice alerts for real-time notification

🧰 Pentest Simulation

Simulates common attack patterns such as:

SQL Injection

Cross-Site Scripting (XSS)

Directory Traversal

Brute-force login attempts

Injects synthetic attack traffic and evaluates detection performance

📊 Interactive Dashboard

Built with Streamlit

Enables:

Dataset upload and preview

Model training and tuning

Visualization of anomalies and explanations

Alert inspection and analysis

🧩 Architecture Summary

Security log data is uploaded as CSV

Features are engineered and normalized

Isolation Forest detects anomalies

A surrogate model enables explainability

SHAP and DiCE provide interpretability

Alerts are generated and stored

Robustness and pentest simulations evaluate system behavior

🧪 Technologies Used

Python

Streamlit

Scikit-learn

Isolation Forest & Random Forest

SHAP (Explainable AI)

DiCE (Counterfactual Explanations)

SQLite

NumPy, Pandas, Matplotlib

⚠️ Scope & Limitations

This is not a signature-based IDS (e.g., Snort, Suricata)

Does not perform raw packet capture or deep packet inspection

Designed for research, education, and applied experimentation, not production SOC deployment

🎯 Key Contributions

Demonstrates anomaly-based intrusion detection using ML

Integrates explainability into cybersecurity decision-making

Evaluates adversarial robustness of security models

Combines IDS logic with SIEM-style alerting and visualization
