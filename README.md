# AI-Driven Real-Time Anomaly Detection and Risk Mitigation in IoT Network

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-Academic-green.svg)

> B.Tech Major Project | CSE (Cyber Security) | VBIT, Hyderabad | 2024-25

## 📌 Overview
A real-time IoT network security tool that captures packets, detects threats using
AI (Isolation Forest), and automatically mitigates attacks like Mirai botnet,
SYN floods, DNS amplification, and behavioral anomalies.

## ✨ Features
- 🔍 **Live Packet Capture** – Captures all network traffic for selected IoT devices
- 🤖 **AI Anomaly Detection** – Uses Isolation Forest (sklearn) to detect behavioral anomalies
- 🦠 **Mirai Botnet Detection** – Identifies brute-force, command injection, and SYN scans
- 🌊 **Flood Detection** – SYN flood, UDP flood, DNS amplification
- 🛡️ **Auto Mitigation** – Block, isolate, or silently monitor malicious devices
- 🔓 **Auto-Unblock** – Automatically unblocks devices once traffic is clean
- 📊 **Live Graph** – Real-time packet flow visualization
- 💾 **Export** – Save captures as `.pcap` (Wireshark-compatible) or `.txt`
- 🖥️ **Cross-Platform** – Works on Windows, Linux, and macOS

## 🛠️ Tech Stack
| Component | Technology |
|-----------|------------|
| Language | Python 3.8+ |
| GUI | Tkinter |
| Packet Capture | Scapy |
| AI/ML | scikit-learn (Isolation Forest) |
| Visualization | Matplotlib |
| Network Scanning | ARP (Scapy) |
| Firewall Control | iptables / netsh / pfctl |

## 📁 Project Structure
## ⚙️ Installation

### Prerequisites
- Python 3.8+
- **Linux/macOS:** Run with `sudo` (required for raw packet capture)
- **Windows:** Run as Administrator

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/iot-anomaly-detection.git
cd iot-anomaly-detection
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the application
```bash
# Linux/macOS
sudo python main.py

# Windows (run terminal as Administrator)
python main.py
```

## 🚀 How to Use
1. Launch the app — it scans your local network automatically
2. Double-click any device in the list to start packet capture
3. Monitor live traffic in the GUI — threats are highlighted in red/orange
4. Click **"Mitigate Threat"** when malicious packets are detected
5. Choose to isolate, temporarily block, or auto-block the device
6. Download the traffic graph or `.pcap` file for further analysis

## 📸 Screenshots
*(Add screenshots of your GUI here)*

## 👨‍💻 Author
**Ch. Akhil Sampath Vinay** (21P61A6209)  
B.Tech CSE (Cyber Security), VBIT Hyderabad  
Guide: Mrs. M. Jhansi Rani, Sr. Assistant Professor

## 🙏 Acknowledgements
- Mrs. M. Jhansi Rani (Internal Guide)
- Mr. K. Ashok (Project Coordinator)
- Dr. P. Sushma (Head of Department)
- Vignana Bharathi Institute of Technology

## 📄 License
This project was submitted as a B.Tech Major Project at VBIT, Hyderabad (2024-25).
