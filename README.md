# 🛡️ Solo Security Lab

A safe, self-contained Python desktop app that teaches you what four common cyberattack patterns look like in real server logs — running entirely on your own computer with zero risk.

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Tkinter](https://img.shields.io/badge/Tkinter-GUI-blue?style=for-the-badge)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Beginner-red?style=for-the-badge)

---

## 📸 Screenshot

> _Add your screenshot here after taking it_

---

## 💡 What It Does

Solo Security Lab is a cybersecurity learning tool built entirely in Python. It is a practice environment that lets a complete beginner experience what a real cyberattack looks like in server logs — without any risk, without extra software, and without touching any real network.

When you run it, **three things start at the same time inside one window:**

- 🖥️ **Fake Web Server** — boots up automatically at `127.0.0.1:8080`, acting as your "target" and writing log entries exactly like a real Apache web server
- ⚔️ **Attack Panel** — 5 buttons, each firing a different simulated attack at the fake server
- 📋 **Live Log Viewer** — shows every request the moment it arrives, colour-coded by attack type

---

## 🔴 The 5 Attack Types

| Attack | Description |
|---|---|
| **Rapid Flood** | Sends a burst of requests to simulate a DoS attempt |
| **Directory Scan** | Probes common URL paths like a real recon tool |
| **Fake Scanner** | Mimics automated vulnerability scanner behaviour |
| **Stealth Probe** | Slow, spaced-out requests designed to avoid detection |
| **All Combined** | Fires all four attacks at once |

---

## ✨ Features

- ✅ Live colour-coded log viewer
- ✅ Scoreboard tracking requests per attack type
- ✅ Export full log as a `.txt` file
- ✅ Built-in help guide
- ✅ Runs 100% on your own machine — no internet needed
- ✅ No extra installs — just Python

---

## 🚀 How to Run

```bash
# clone the repo
git clone https://github.com/G1H6-bit/solo-security-lab.git
cd solo-security-lab

# run the app
python solo_security_lab.py
```

> Requires Python 3.x — no extra libraries needed (uses built-in tkinter)

---

## 🎯 Who Is It For

Anyone just starting out in cybersecurity who wants to **see attack concepts in action** before moving on to a full virtual machine lab. This project gives you a safe, visual way to understand what flood attacks, recon scans, and stealth probes actually look like in server logs.

---

## 👤 Author

**Abdelrahman Ashraf**
- GitHub: [@G1H6-bit](https://github.com/G1H6-bit)
- LinkedIn: [Abdelrahman Ashraf](https://www.linkedin.com/in/abdelrahman-ashraf-39169035a/)

---

## 📄 License

Open source — MIT License
