# Privacy Shield 🛡️

> Android security & privacy app — WiFi/BLE device detection, network analysis, CVE lookup, and security tools suite

![Platform](https://img.shields.io/badge/platform-Android-green?style=flat-square&logo=android)
![Kotlin](https://img.shields.io/badge/kotlin-2.1.0-purple?style=flat-square&logo=kotlin)
![Min SDK](https://img.shields.io/badge/minSdk-21-blue?style=flat-square)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-orange?style=flat-square)

Privacy Shield is an Android security and privacy application built with Kotlin and Jetpack Compose. It scans for nearby WiFi and Bluetooth devices, identifies potential threats, and provides a full suite of network security tools — all from your phone.

---

## Screenshots

<!-- Add screenshots here after first release -->
| Home | Network | Tools | Device Detail |
|------|---------|-------|---------------|
| *coming soon* | *coming soon* | *coming soon* | *coming soon* |

---

## Features

### 🔍 Device Detection
- WiFi and Bluetooth LE scanning with real-time updates
- 13 device type classifications: Camera, Microphone, Router, IoT, Phone, Tablet, and more
- Distance calculation using Free-Space Path Loss (FSPL) formula
- Privacy score (0–100) weighted by device type and proximity
- MAC vendor identification — local OUI database (~500 entries) + API fallback
- Signal history tracking per device

### 🌐 Network Analysis
- Connected network info: SSID, BSSID, IP, gateway, DNS
- Host discovery (subnet ping scan)
- DNS leak check
- Security analysis: open WiFi, DNS security, gateway exposure, IP privacy
- **Passive evil twin / rogue AP detection** — flags duplicate SSIDs with mismatched OUIs

### 🛠️ Security Tools
- **Port Scanner** — preset groups (Common, Web, Database, IoT), custom range, risk-labeled results
- **Ping** — with mini bar graph of last 5 results
- **WHOIS Lookup** — powered by ipinfo.io
- **Traceroute** — TCP-based, live hop results
- **CVE Lookup** — searches CIRCL and NVD databases with severity badges
- **Python Scanner** — pure TCP host discovery and service detection (Chaquopy-powered)

### 🔒 Security & Privacy
- Biometric app lock (crash-safe, graceful degradation)
- Background scanning via WorkManager with configurable intervals
- Push notifications for suspicious devices and evil twin detection
- Scan history with Room database, CSV and PDF export

### ⚙️ Settings
- Dark / Light theme with persistence
- Background scan interval (15/30/60/120 min)
- Clear history, export data, about screen

---

## Build Variants

| Branch | Description | Root Required |
|--------|-------------|---------------|
| `main` | Release build — Play Store safe | No |
| `dev` | Full build — extended root features | Optional |

Root features (dev build only): true ICMP traceroute, nmap binary scanning via Chaquopy, raw socket operations.
The dev build (root features) is distributed separately — see Releases.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Kotlin 2.1.0 |
| UI | Jetpack Compose + Material3 |
| Architecture | Single Activity, MVVM, State hoisting |
| Database | Room 2.6.1 (KSP) |
| Background | WorkManager 2.9.0 |
| Python | Chaquopy 16.0.0 (Python 3.11) |
| Auth | AndroidX Biometric 1.1.0 |
| Build | AGP 8.7.3, Gradle 8.9 |

---

## Requirements

- Android 5.0+ (minSdk 21)
- Target SDK 34
- Java: Android Studio JBR (included)
- For dev build: rooted device recommended

---

## Building

```bash
# Clone the repo
git clone https://github.com/cuenca125/privacy-shield.git
cd privacy-shield

# Build debug APK
.\gradlew.bat assembleDebug        # Windows
./gradlew assembleDebug            # Linux/Mac

# Install to connected device
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### Enable root features (dev build)

In `app/build.gradle.kts`, change:
```kotlin
buildConfigField("boolean", "ENABLE_ROOT_FEATURES", "false")
// to:
buildConfigField("boolean", "ENABLE_ROOT_FEATURES", "true")
```

---

## Project Structure

```
app/src/main/java/com/privacyshield/
  MainActivity.kt          # ~2000 lines — entire app UI and logic
  ScanWorker.kt            # WorkManager background scanning
  PythonBridge.kt          # Chaquopy Python bridge
  OuiLookup.kt             # MAC OUI database + API lookup
  EvilTwinDetector.kt      # Passive rogue AP detection
  RootFeatureGate.kt       # Root capability detection and gating
  data/
    DeviceHistoryEntity.kt
    DeviceHistoryDao.kt
    AppDatabase.kt
    ScanSessionSummary.kt

app/src/main/python/
  nmap_scanner.py          # Pure socket host/service scanner (Tier 1)
  nmap_scanner_root.py     # nmap binary wrapper (Tier 2, root only)
  scapy_inspector.py       # Scapy interface inspector

app/src/main/assets/
  oui_database.txt         # ~500 OUI prefix entries
```

---

## Known Limitations

- Android MAC randomization (API 29+) means most devices return locally administered MACs — vendor lookup unavailable for these
- Traceroute uses TCP port 80 connect, not true ICMP — some hosts may not respond
- Python Scanner uses pure TCP connect in release build — hosts blocking all TCP ports may appear offline
- Chaquopy adds ~40MB to APK size
- Biometric lock disabled automatically on devices with unlocked bootloader
- Background scan dedup threshold: 120 seconds

---

## Roadmap

- [ ] GitHub Actions CI/CD pipeline
- [ ] Play Store publication
- [ ] True ICMP traceroute (root/dev build)
- [ ] WPA handshake capture (monitor mode, root)
- [ ] Evil twin active detection (root)
- [ ] CVE lookup integration with detected device manufacturers
- [ ] IPv6 support
- [ ] Widget for home screen privacy score

---

## Author

**Juan** — [@blank-0x](https://github.com/blank-0x)  
Cybersecurity enthusiast · CompTIA Security+ candidate

---

## License

MIT License — see [LICENSE](LICENSE) for details.
