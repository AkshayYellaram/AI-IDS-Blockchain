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

### Supported approaches

| Model / Technique | Purpose |
|---|---|
| Random Forest | Supervised intrusion classification |
| Extra Trees | Tree-based classification |
| Gradient Boosting | Supervised classification |
| Isolation Forest | Anomaly detection |
| Ensemble Detector | Combines multiple detection approaches |
| Multi-Dataset Detector | Works across multiple network-security datasets |

---

# ⛓️ Blockchain Security Layer

The blockchain component provides a mechanism for storing generated security alerts on an Ethereum-compatible local blockchain.

### Architecture

```text
┌──────────────────────┐
│   IDS / ML Engine    │
└──────────┬───────────┘
           │
           │ Security Alert
           ▼
┌──────────────────────┐
│  Blockchain Logger   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   AlertStorage.sol   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│       Ganache        │
│  Local Blockchain    │
└──────────────────────┘
```

The smart contract is located at:

```text
blockchain/AlertStorage.sol
```

The local blockchain configuration is stored in:

```text
blockchain/blockchain_config.py
```

The default development RPC endpoint is:

```text
http://127.0.0.1:7545
```

> ⚠️ The repository should never contain wallet private keys, API keys, passwords, or other credentials.

---

# 📂 Project Architecture

```text
AI-IDS-Blockchain/
│
├── 🧱 blockchain/
│   ├── AlertStorage.sol
│   ├── AlertStorage_abi.json
│   ├── blockchain_config.py
│   ├── blockchain_logger.py
│   ├── store_alert.py
│   ├── store_test_alert.py
│   ├── test_blockchain.py
│   └── test_logger.py
│
├── 📡 capture/
│   └── live_capture.py
│
├── 📊 dashboard/
│   ├── index.html
│   └── main.py
│
├── 🌐 flows/
│   └── flow_monitor.py
│
├── 🤖 ml/
│   ├── decision_engine.py
│   ├── ensemble_detector.py
│   ├── live_predictor.py
│   ├── multi_dataset_detector.py
│   ├── train_model.py
│   ├── train_ensemble.py
│   ├── train_cicids_models.py
│   ├── train_isolation_forest.py
│   ├── evaluate_decision_engine.py
│   └── verify_real_attack.py
│
├── 🛠️ tools/
│   └── prepare_cicids.py
│
├── ids_engine.py
├── ids_engine_multidataset.py
├── ids_engine_multidataset_backup.py
└── README.md
```

---

# 📚 Datasets

The project works with network intrusion-detection datasets including:

### CICIDS2017

Used for training and evaluating network intrusion detection models.

### UNSW-NB15

Used as an additional network-security dataset for multi-dataset experimentation.

### Repository policy

The original datasets are **not included in this GitHub repository** because of their large file sizes.

They are excluded through `.gitignore` while remaining available locally for development and experimentation.

---

# 🖥️ Dashboard

The project includes a dashboard component for interacting with the IDS system and viewing security-related information.

Main dashboard files:

```text
dashboard/index.html
dashboard/main.py
```

> 📸 **Dashboard screenshots can be added here later.**

Example:

```text
docs/
└── dashboard.png
```

Then embed the screenshot with:

```markdown
![AI-IDS Dashboard](docs/dashboard.png)
```

---

# ⚙️ Installation

## 1. Clone the repository

```bash
git clone https://github.com/AkshayYellaram/AI-IDS-Blockchain.git
cd AI-IDS-Blockchain
```

## 2. Create a virtual environment

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

If a dependency file is provided:

```bash
pip install -r requirements.txt
```

## 4. Prepare the datasets

Place the required datasets in the local `dataset/` directory.

The datasets are intentionally excluded from GitHub.

## 5. Start Ganache

Run a local Ganache blockchain and deploy:

```text
blockchain/AlertStorage.sol
```

Update the deployed contract address in:

```text
blockchain/blockchain_config.py
```

---

# 🧪 Development & Testing

The repository contains separate scripts for testing different components.

### Blockchain

```text
blockchain/test_blockchain.py
blockchain/test_logger.py
```

### ML

```text
ml/test_prediction.py
ml/evaluate_decision_engine.py
ml/verify_real_attack.py
```

---

# 🔐 Security Considerations

This project is intended for **research, educational, and experimental cybersecurity use**.

Machine-learning-based intrusion detection can produce:

- False positives
- False negatives
- Dataset-dependent results
- Performance differences between simulated and real-world traffic

Therefore, the system should not be treated as a guaranteed replacement for a production security monitoring system.

---

# 🛠️ Technology Stack

| Category | Technologies |
|---|---|
| Programming | Python |
| Machine Learning | Scikit-learn |
| Data Processing | Pandas |
| Network Analysis | Scapy |
| Smart Contracts | Solidity |
| Blockchain | Ganache / Ethereum-compatible network |
| Frontend | HTML / JavaScript |
| Version Control | Git / GitHub |

---

# 🎯 Project Objectives

The project explores the combination of **AI, cybersecurity, and blockchain** into a single security-monitoring workflow.

### Primary objectives

- Detect potentially malicious network activity using ML
- Experiment with multiple intrusion-detection models
- Support network-flow monitoring
- Generate structured security alerts
- Store alerts through a blockchain-backed component
- Explore multi-dataset intrusion detection
- Provide a dashboard for system interaction

---

# 🔭 Future Improvements

Potential improvements include:

- [ ] Real-time network monitoring improvements
- [ ] Better model explainability
- [ ] More extensive model evaluation
- [ ] Additional intrusion-detection datasets
- [ ] Improved dashboard visualization
- [ ] Remote blockchain deployment
- [ ] Alert correlation and investigation features
- [ ] Containerized deployment

---

# 👨‍💻 Author

## Akshay Yellaram

Cybersecurity & IoT Student

Interested in:

**Cybersecurity · AI/ML · Digital Forensics · Blockchain · Ethical Hacking**

<p align="center">

⭐ If you find this project interesting, consider giving the repository a star!

</p>
