# Reading Network Packets & Intrusion Detection System (IDS)

## 📌 Project Overview

This project is a Python-based network traffic analysis and packet inspection tool built using **PyShark**. It demonstrates how packet captures can be read, analyzed, and inspected for security monitoring and intrusion detection purposes.

The project serves as an introduction to:
- Packet sniffing
- Network protocol analysis
- Intrusion Detection System (IDS) fundamentals

---

## 🧩 Project Structure

├── main.py # Entry point for packet capture and analysis
├── IDS.py # IDS class handling packet inspection logic
├── Conf.conf # Configuration file for capture settings


---

## 🔍 Features

- Live packet capture using PyShark
- PCAP stream inspection
- Transport layer detection
- Basic packet logging and output
- Configurable capture behavior
- Exception handling for TShark crashes

---

## ⚙️ How It Works (High-Level)

1. Configuration values are loaded from `Conf.conf`
2. PyShark initializes a packet capture
3. Packets are read from the network interface or PCAP stream
4. Packet data is analyzed and displayed
5. The IDS logic inspects traffic for analysis purposes

---

## 🛠️ Technologies Used

- Python 3
- PyShark
- TShark
- Network packet analysis
- Object-oriented design

---

## 📚 Educational Use Cases

- Learning packet structure and protocols
- Understanding how IDS systems work
- Network traffic analysis
- Cybersecurity and networking labs

---

## ⚠️ Requirements

- Python 3.x
- Wireshark / TShark installed
- PyShark library

> Packet capture may require elevated privileges depending on your OS.


