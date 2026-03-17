# Privacy Policy — Privacy Shield

_Last updated: March 2026_

## Overview

Privacy Shield ("the app") is an Android application that scans for nearby WiFi and Bluetooth LE devices and classifies them by type (cameras, microphones, routers, IoT devices, etc.) to help users understand their local network environment.

## Data We Collect

### Device Scan Data
The app scans for nearby wireless devices and stores the following locally on your device:
- Device name (SSID or Bluetooth advertised name)
- MAC address
- Signal strength (RSSI)
- Device type classification
- Scan timestamp and session ID
- Whether a device was marked suspicious or safe

**All scan data is stored exclusively on your device** in a local Room database. No scan data is transmitted to our servers.

### Network Information
When you use the Network tab, the app reads:
- Your connected WiFi network name and BSSID
- Local IP address and gateway IP
- DNS server addresses

This information is displayed to you and never transmitted externally.

### WHOIS / IP Lookup
The WHOIS tool sends queries to `ipinfo.io` — a third-party service. When you look up an IP address, that IP is sent to ipinfo.io per their [privacy policy](https://ipinfo.io/privacy-policy).

### MAC Vendor Lookup
The app may query `api.macvendors.com` to identify the manufacturer of a device's MAC address. Only the MAC OUI prefix (first 3 octets) is sent; full MAC addresses are never transmitted.

### CVE Lookup
The CVE tool queries `cve.circl.lu` and optionally `nvd.nist.gov`. Search terms you enter are sent to these APIs.

## Data We Do NOT Collect

- We do not collect any personal information
- We do not use analytics or crash reporting SDKs
- We do not transmit device scan results to any server
- We do not track your location
- We do not access your contacts, camera, or microphone (the microphone permission is not used)
- We do not show advertisements

## Permissions

| Permission | Purpose |
|---|---|
| `ACCESS_FINE_LOCATION` | Required by Android to scan for WiFi networks and BLE devices |
| `BLUETOOTH_SCAN` | Scan for nearby Bluetooth LE devices |
| `BLUETOOTH_CONNECT` | Read device names during BLE scan |
| `ACCESS_WIFI_STATE` | Read WiFi scan results and current connection info |
| `INTERNET` | WHOIS lookups, MAC vendor lookups, CVE queries |
| `USE_BIOMETRIC` | Optional app lock using device biometrics |

Location permission is required by Android OS policy for WiFi and Bluetooth scanning — the app does not request or store your GPS location.

## Data Retention

Scan history is stored locally and can be deleted at any time via **Settings → Clear All App Data** or **Settings → Clear Old History**. Individual scan sessions can also be deleted from the History tab.

## Background Scanning

If you enable Background Scanning, the app uses Android WorkManager to periodically scan for devices and send a local notification if suspicious devices are found. No data leaves your device during background scans.

## Children's Privacy

This app is not directed at children under 13 and does not knowingly collect information from children.

## Changes to This Policy

We may update this privacy policy. The "Last updated" date at the top of this page will reflect any changes.

## Contact

For questions about this privacy policy or to report a security issue, please open an issue on our GitHub repository:

[https://github.com/blank-0x/privacy-shield](https://github.com/blank-0x/privacy-shield)
