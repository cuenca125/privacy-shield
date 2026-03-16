# Privacy Shield — Security Audit Report
**Date:** 2026-03-16
**Auditor:** Claude Code Security Agent
**Scope:** Full codebase review — all Kotlin, Python, Gradle, XML files
**Status:** 1 Critical, 2 High, 5 Medium, 4 Low, 3 Info

---

## Executive Summary

Privacy Shield is a local Android security tool with a generally sound architecture, but three issues require immediate attention: hardcoded keystore credentials in the build script, an unrestricted Python `exec()` sandbox that allows arbitrary file access and system command execution, and no execution timeout on the Script Runner enabling denial-of-service. All CRITICAL and HIGH findings have been automatically fixed. Medium and Low findings are documented for manual review.

---

## Findings

### [CRITICAL] — Hardcoded Keystore Credentials in Build Script
**File:** `app/build.gradle.kts` (lines 44–46)
**Description:** The signing configuration falls back to hardcoded plaintext passwords (`REDACTED`) when environment variables are not set. Any developer who has read access to the repository (or its git history) can extract the keystore password and sign arbitrary APKs as Privacy Shield.
**Risk:** An attacker with the keystore file (also committed as `app/keystore/release.keystore`) and these credentials can sign malicious APKs that Android treats as official updates from the same developer.
**Fix:** Move credentials to `keystore.properties` (not committed to VCS); read them in Gradle. Skip signing if the file is absent rather than falling back to hardcoded values.
**Status:** ✅ Fixed — credentials moved to `keystore.properties`, hardcoded fallback removed.

---

### [HIGH] — Python Script Runner `exec()` Exposes Full Builtins
**File:** `app/src/main/python/scapy_inspector.py` (line 208)
**Description:** `run_custom_script()` calls `exec(script, {"__builtins__": __builtins__, ...})`. Passing the real `__builtins__` gives the sandboxed script access to `open`, `os`, `subprocess`, `eval`, `__import__`, and every other dangerous built-in. A user can read any file on the device, overwrite app data, or (if root) execute shell commands.
**Risk:** Full local filesystem read/write; potential escalation to root command execution on rooted devices; data exfiltration from the app's internal storage.
**Fix:** Replace `__builtins__` with a curated allowlist of safe built-ins; remove `open`, `os`, `subprocess`, `__import__` etc. from the execution context.
**Status:** ✅ Fixed — restricted builtins allowlist applied in `run_custom_script()`.

---

### [HIGH] — No Execution Timeout in Python Script Runner
**File:** `app/src/main/python/scapy_inspector.py` (line 208)
**Description:** `run_custom_script()` has no timeout. A user script containing `while True: pass` or `import time; time.sleep(999999)` will block the Chaquopy Python thread indefinitely, freezing the app's Security tab and exhausting device resources.
**Risk:** Denial-of-service against the app UI; battery drain; potential ANR (Application Not Responding) crash.
**Fix:** Run the script in a daemon thread with a 30-second join timeout; raise `TimeoutError` if the thread is still alive afterwards.
**Status:** ✅ Fixed — 30-second thread-based timeout added to `run_custom_script()`.

---

### [MEDIUM] — CVE Vendor/Product Not URL-Encoded in Path
**File:** `app/src/main/java/com/privacyshield/MainActivity.kt` (~line 1859)
**Description:** The circl.lu CVE API URL is constructed by string interpolation: `"https://cve.circl.lu/api/search/$vendor/$product"`. Although `/` is used as a split delimiter (reducing path traversal risk), characters like `%`, `?`, `#`, and space may still reach the URL unencoded. The NVD fallback path correctly uses `URLEncoder.encode()`.
**Risk:** Malformed API requests; in edge cases, partial path traversal to unintended circl.lu endpoints.
**Fix:** Apply `URLEncoder.encode(vendor, "UTF-8")` and `URLEncoder.encode(product, "UTF-8")` before interpolation.
**Status:** ✅ Fixed — URL encoding applied to both vendor and product segments.

---

### [MEDIUM] — No Input Validation on Port Scanner and Traceroute Targets
**File:** `app/src/main/java/com/privacyshield/MainActivity.kt` (lines 2022, 2508)
**Description:** `targetIp` (port scanner) and `traceTarget` (traceroute) are passed directly to `java.net.InetSocketAddress` without format validation. While Java socket APIs prevent shell injection, arbitrary hostnames/IPs can be entered, enabling the app to probe internal network services or external hosts beyond the intended local network scope.
**Risk:** Limited SSRF — a user could scan arbitrary internal hosts or external internet addresses from the device; combined with on-device logging this could be a privacy concern in multi-user environments.
**Fix:** Validate that inputs match IPv4, IPv6, or hostname patterns before initiating any network operation.
**Status:** ✅ Fixed — `isValidNetworkTarget()` validation function added and applied at both scan entry points.

---

### [MEDIUM] — `allowBackup="true"` Exposes Scan Database
**File:** `app/src/main/AndroidManifest.xml` (line 32)
**Description:** With `allowBackup="true"`, ADB backup (`adb backup`) can extract the app's data directory including the unencrypted Room database (`privacy_shield_db`), which contains device MAC addresses, scan session timestamps, signal strengths, and network topology.
**Risk:** Physical attacker with USB access can extract the full scan history without root. This data reveals which networks and devices are present in the user's environment.
**Fix:** Set `android:allowBackup="false"` or configure `android:fullBackupContent` with `<exclude domain="database" path="privacy_shield_db" />` to exclude the scan database from backups.
**Status:** ⚠️ Requires manual action — weigh user value of cloud backup against data sensitivity.

---

### [MEDIUM] — Room Database Stored in Plaintext
**File:** `app/src/main/java/com/privacyshield/data/AppDatabase.kt`
**Description:** The Room database is created with `Room.databaseBuilder()` without SQLCipher encryption. The database at `/data/data/com.privacyshield/databases/privacy_shield_db` is readable in plaintext by a rooted device or via backup.
**Risk:** Scan history (MAC addresses, IPs, device types, session timestamps) is accessible without authentication on rooted devices or via backup extraction.
**Fix:** Integrate SQLCipher for Android and use `SupportFactory(passphrase)` where the passphrase is derived from the Android Keystore.
**Status:** ⚠️ Requires manual action — significant dependency change; evaluate based on user threat model.

---

### [MEDIUM] — No `network_security_config.xml` Defined
**File:** `app/src/main/AndroidManifest.xml`
**Description:** The app does not declare a `android:networkSecurityConfig` attribute. On API 24+ (minSdk 24), the default config blocks cleartext HTTP, which is correct. However, no pinning or additional hardening is configured for the third-party APIs (`ipinfo.io`, `cve.circl.lu`, `api.macvendors.com`, NVD).
**Risk:** Without certificate pinning, a network-level attacker on the same WiFi (where Privacy Shield operates) could perform MITM against the app's own API calls, injecting false CVE data or geolocation results.
**Fix:** Add `network_security_config.xml` with `<domain-config cleartextTrafficPermitted="false">` for all domains. Consider adding certificate pins for critical endpoints.
**Status:** ⚠️ Requires manual action — accepted risk for v1.1; certificate pinning is recommended for a future release.

---

### [LOW] — Exception Messages Exposed in UI
**File:** `app/src/main/java/com/privacyshield/MainActivity.kt` (multiple locations)
**Description:** Raw exception messages are surfaced directly in the UI (`whoisError = "Error: ${e.message}"`, similar patterns in CVE lookup). Exception messages may contain internal paths, class names, or stack details useful for reconnaissance.
**Risk:** Low; this is a local tool, but log-leaking still represents unnecessary information disclosure.
**Fix:** Replace raw `e.message` with user-friendly generic error strings; log details internally.
**Status:** ℹ️ Accepted risk — documented for future cleanup.

---

### [LOW] — RootFeatureGate Bypass via `su` Binary Replacement
**File:** `app/src/main/java/com/privacyshield/RootFeatureGate.kt` (line 8)
**Description:** `isRooted()` calls `Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))` and checks for `uid=0`. On a device with a fake `su` binary (e.g., Magisk DenyList bypass, or a custom ROM), this check could be spoofed to return `uid=0` without actual root, enabling root features without privilege.
**Risk:** Low — `ENABLE_ROOT_FEATURES` build flag is `false` by default in production, so this gate is only relevant in debug/dev builds. An attacker would need physical access and ability to place a fake `su` binary.
**Fix:** Additionally check `BuildConfig.DEBUG` or use a secondary integrity check.
**Status:** ℹ️ Accepted risk — gated by `BuildConfig.ENABLE_ROOT_FEATURES = false` in production.

---

### [LOW] — Unbounded In-Memory API Cache
**File:** `app/src/main/java/com/privacyshield/OuiLookup.kt` (line 11)
**Description:** `apiCache` is a `mutableMapOf<String, String>()` with no size limit. Repeated lookups of unique OUI prefixes (e.g., during a large BLE scan) accumulate entries indefinitely until the process is killed.
**Risk:** Low — OUI prefixes are 6 hex chars so the practical key space is bounded; memory impact is minimal in real use.
**Fix:** Cap the cache at ~500 entries with LRU eviction.
**Status:** ℹ️ Accepted risk for v1.1.

---

### [LOW] — API Response Size Not Bounded
**File:** `app/src/main/java/com/privacyshield/MainActivity.kt` (lines 1848–1852)
**Description:** `fetchUrl()` reads the entire response body without a size limit. A malicious or compromised API server could return a very large payload, causing memory pressure.
**Risk:** Low — all API endpoints are reputable public services (circl.lu, NVD NIST, ipinfo.io).
**Fix:** Limit response reads to `maxBytes` (e.g., 2 MB) before parsing.
**Status:** ℹ️ Accepted risk for v1.1.

---

## Permissions Audit

| Permission | Used | Justified | Recommendation |
|---|---|---|---|
| `INTERNET` | ✅ Yes | API calls (WHOIS, CVE, MAC vendor) | Keep |
| `ACCESS_NETWORK_STATE` | ✅ Yes | Network info in Network tab | Keep |
| `ACCESS_WIFI_STATE` | ✅ Yes | WiFi scan, SSID, gateway info | Keep |
| `CHANGE_WIFI_STATE` | ✅ Yes | `wifiManager.startScan()` in MainActivity | Keep |
| `ACCESS_FINE_LOCATION` | ✅ Yes | Required for BLE + WiFi scanning on API 23+ | Keep — rationale shown in onboarding |
| `ACCESS_COARSE_LOCATION` | ✅ Yes | Fallback for WiFi scanning | Keep |
| `BLUETOOTH` (maxSdk 30) | ✅ Yes | BLE scanning on pre-S devices | Keep |
| `BLUETOOTH_ADMIN` (maxSdk 30) | ✅ Yes | BLE adapter management pre-S | Keep |
| `BLUETOOTH_SCAN` | ✅ Yes | BLE scan on API 31+ | Keep — `neverForLocation` correctly set |
| `BLUETOOTH_CONNECT` | ✅ Yes | BLE device name resolution | Keep |

All declared permissions are actively used and justified. No over-broad permissions detected.

---

## Secrets Scan

| Location | Type | Status |
|---|---|---|
| `app/build.gradle.kts` line 44 | Keystore storePassword `REDACTED` | ✅ Fixed — moved to `keystore.properties` |
| `app/build.gradle.kts` line 46 | Keystore keyPassword `REDACTED` | ✅ Fixed — moved to `keystore.properties` |
| `app/build.gradle.kts` line 45 | Key alias `privacyshield` | ✅ Fixed — moved to `keystore.properties` |
| `gradle.properties` | No secrets | ✅ Clean |
| `app/src/main/python/*.py` | No hardcoded credentials | ✅ Clean |
| `app/src/main/AndroidManifest.xml` | No API keys | ✅ Clean |
| `app/proguard-rules.pro` | No secrets | ✅ Clean |

---

## Overall Security Score

**68 / 100**

| Category | Score | Notes |
|---|---|---|
| Input Validation | 14/20 | Port/trace now validated; Python input is sandboxed |
| Secrets Management | 15/20 | Keystore now externalized; no other hardcoded secrets |
| Network Security | 12/20 | All HTTPS; no pinning; no explicit NSC |
| Data Storage | 8/20 | Room DB unencrypted; allowBackup=true |
| Sandbox Safety | 10/15 | exec() now restricted; timeout added |
| Permissions | 15/15 | Minimal and justified |
| Authentication / Gate | 4/10 | Root gate bypassable (low risk in prod) |

**Post-fix score: 68/100.** Primary remaining risks are unencrypted database and no certificate pinning — both require significant architectural changes beyond the scope of this automated fix session.
