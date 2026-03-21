<div align="center">
  <img src="screenshots/ic_launcher-playstore.png" width="100" alt="Privacy Shield Logo"/>
  <h1>Privacy Shield</h1>
  <p>Android security and privacy app for detecting nearby devices, scanning networks, and running advanced security tools.</p>

  ![Android](https://img.shields.io/badge/Android-21%2B-green?logo=android)
  ![Kotlin](https://img.shields.io/badge/Kotlin-2.1.0-purple?logo=kotlin)
  ![License](https://img.shields.io/badge/License-MIT-blue)
  ![Release](https://img.shields.io/badge/Release-v1.1-brightgreen)
</div>

---

## Screenshots

<div align="center">
  <img src="screenshots/home.jpg" width="30%" alt="Home Tab"/>
  <img src="screenshots/tools.jpg" width="30%" alt="Tools Tab - CVE Lookup"/>
  <img src="screenshots/security.jpg" width="30%" alt="Security Tab"/>
</div>

---

## Features

### Device Detection
- BLE and WiFi device scanning with 13 device types
- Privacy scoring system with real-time breakdown
- MAC vendor lookup via local database + API fallback
- Mark devices as safe or suspicious
- Background scanning with configurable intervals

### Network Tools
- Port scanner with preset groups and risk labeling
- Ping with live signal graph
- WHOIS / IP geolocation lookup
- TCP traceroute (no root required)
- Host discovery and DNS leak check

### CVE Lookup
- Search by vendor or product name
- Dual API fallback: CIRCL + NVD
- Severity badges (Critical / High / Medium / Low)

### Security Tab (Root Required)
- Nmap Deep Scan — OS detection, service versions, vulnerability scripts
- Scapy Analyzer — packet inspection and protocol analysis
- WPA Handshake Capture — capture WPA/WPA2 handshakes for authorized testing
- ARP Poisoning Detection — detect MITM attacks on your network
- Active Evil Twin Detection — identify rogue access points
- Network Traffic Monitor — live connection stats
- Python Script Runner — run custom Scapy scripts

### Privacy & Data
- Scan history stored in Room database
- CSV and PDF export
- Biometric app lock
- No telemetry, no ads, no cloud

---

## Tech Stack

| Layer | Tech |
|---|---|
| Language | Kotlin 2.1.0 |
| UI | Jetpack Compose + Material3 |
| Database | Room 2.6.1 |
| Background | WorkManager |
| Root tools | Chaquopy (Python), Nmap binary |
| Architecture | MVVM, single Activity |
| Min SDK | 21 (Android 5.0) |

---

## Build

```bash
git clone https://github.com/blank-0x/privacy-shield.git
cd privacy-shield
./gradlew assembleRelease
```

Requires Android Studio Hedgehog or later.

---

## Repos

| Repo | Description |
|---|---|
| [blank-0x/privacy-shield](https://github.com/blank-0x/privacy-shield) | Public release build — Play Store safe |
| [blank-0x/privacy-shield-dev](https://github.com/blank-0x/privacy-shield-dev) | Private dev build — includes root features, nmap binary |

---

## Privacy Policy

[https://blank-0x.github.io/privacy-shield/](https://blank-0x.github.io/privacy-shield/)

---

## License

MIT © blank-0x
