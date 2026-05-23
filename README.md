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
