# 🛡️ AI-IDS-Blockchain

### AI-Powered Intrusion Detection with Blockchain-Backed Security Alerts

<p align="center">

**Machine Learning** · **Network Security** · **Intrusion Detection** · **Blockchain**

</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Scikit--Learn-ML-orange?style=for-the-badge&logo=scikit-learn" alt="Scikit-Learn">
  <img src="https://img.shields.io/badge/Solidity-Smart%20Contracts-black?style=for-the-badge&logo=solidity" alt="Solidity">
  <img src="https://img.shields.io/badge/Ganache-Blockchain-EF7B4D?style=for-the-badge" alt="Ganache">
  <img src="https://img.shields.io/badge/Cybersecurity-IDS-red?style=for-the-badge" alt="Cybersecurity">
</p>

---

## 🚀 What is AI-IDS-Blockchain?

**AI-IDS-Blockchain** is a cybersecurity project that combines **machine-learning-based intrusion detection** with **blockchain-backed security alert storage**.

The system analyzes network traffic and flow information, applies multiple machine-learning approaches to identify potentially malicious activity, generates security alerts, and provides a blockchain component for storing those alerts.

### The core idea

```text
        🌐 Network Traffic
                │
                ▼
       📡 Traffic / Flow Capture
                │
                ▼
        ⚙️ Feature Processing
                │
                ▼
       🤖 ML Intrusion Detection
                │
                ▼
       🧠 Decision / Ensemble
                │
          ┌─────┴─────┐
          ▼           ▼
     🚨 Security    📊 Dashboard
        Alert
          │
          ▼
     ⛓️ Blockchain
     Alert Storage
```

---

# ✨ Key Features

<table>
<tr>
<td width="50%">

### 🤖 AI-Based Detection

Multiple machine-learning approaches are included for network intrusion detection:

- Random Forest
- Extra Trees
- Gradient Boosting
- Isolation Forest
- Ensemble detection
- Multi-dataset detection

</td>

<td width="50%">

### 🌐 Network Monitoring

The project includes components for:

- Network traffic capture
- Flow monitoring
- Feature preparation
- Live prediction
- Security alert generation

</td>
</tr>

<tr>
<td>

### ⛓️ Blockchain Integration

Security alerts can be stored using a Solidity smart contract.

Includes:

- Smart contract
- Contract ABI
- Blockchain logger
- Alert storage scripts
- Blockchain tests
- Ganache integration

</td>

<td>

### 📊 Monitoring Dashboard

A web-based dashboard is included for interacting with and visualizing the IDS components.

</td>
</tr>
</table>

---

# 🧠 Machine Learning Pipeline

The project contains several ML components that can be used independently or together.

```text
                 Network Dataset
                       │
                       ▼
              Data Preparation
                       │
                       ▼
              Feature Processing
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
     Random Forest  Extra Trees  Gradient Boosting
          │            │            │
          └────────────┼────────────┘
                       ▼
                Ensemble / Decision
                       │
                       ▼
              Intrusion Prediction
                       │
                       ▼
                 Security Alert
```

### Supported
