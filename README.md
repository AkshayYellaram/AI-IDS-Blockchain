\# AI-IDS-Blockchain



An AI-powered Intrusion Detection System (IDS) that combines machine learning-based network traffic analysis with blockchain-backed security alert storage.



\## Overview



\*\*AI-IDS-Blockchain\*\* is a cybersecurity project designed to analyze network traffic, identify potentially malicious activity using machine-learning models, and store security alerts through a blockchain-based component.



The project combines three major areas:



\- 🤖 \*\*Artificial Intelligence / Machine Learning\*\* — network intrusion detection

\- 🛡️ \*\*Cybersecurity\*\* — traffic monitoring and security alert generation

\- ⛓️ \*\*Blockchain\*\* — tamper-resistant storage of security alerts



The system supports analysis using datasets such as \*\*CICIDS2017\*\* and \*\*UNSW-NB15\*\*, along with live network-flow monitoring components.



\## Key Features



\### Machine-Learning Intrusion Detection



The project includes multiple ML-based detection approaches, including:



\- Random Forest

\- Extra Trees

\- Gradient Boosting

\- Isolation Forest

\- Ensemble-based detection

\- Multi-dataset detection



The trained model files are intentionally \*\*not included in this repository\*\* because of their large size.



\### Network Monitoring



The project includes components for:



\- Network traffic capture

\- Flow monitoring

\- Feature preparation

\- Live prediction

\- Security alert generation



\### Blockchain Alert Storage



Detected security alerts can be stored using a Solidity smart contract.



The project includes:



\- `AlertStorage.sol`

\- Contract ABI

\- Blockchain logger

\- Alert storage scripts

\- Blockchain testing scripts

\- Local Ganache integration



The default configuration uses a local Ganache RPC endpoint.



\### Dashboard



A web dashboard is included for viewing and interacting with the IDS components.



\## System Workflow



```text

Network Traffic

&#x20;     │

&#x20;     ▼

Traffic Capture / Flow Monitoring

