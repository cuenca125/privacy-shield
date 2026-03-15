package com.privacyshield

fun isSamePhysicalRouter(mac1: String, mac2: String, signal1: Int, signal2: Int): Boolean {
    val m1 = mac1.uppercase().replace(":", "")
    val m2 = mac2.uppercase().replace(":", "")
    if (m1.length != 12 || m2.length != 12) return false

    // Compare last 4 octets — dual-band routers use sequential MACs
    val suffix1 = m1.substring(4)
    val suffix2 = m2.substring(4)
    val diffChars = suffix1.zip(suffix2).count { (a, b) -> a != b }
    val signalClose = Math.abs(signal1 - signal2) <= 30

    if (diffChars <= 2 && signalClose) return true

    // Secondary: first octet proximity (wider threshold)
    val oui1First = m1.substring(0, 2).toIntOrNull(16) ?: return false
    val oui2First = m2.substring(0, 2).toIntOrNull(16) ?: return false
    if (Math.abs(oui1First - oui2First) <= 8 && signalClose) return true

    return false
}

fun detectEvilTwins(devices: List<DetectedDevice>): List<EvilTwinAlert> {
    val alerts = mutableListOf<EvilTwinAlert>()
    val wifiDevices = devices.filter { it.protocol == "WiFi" }
    val hiddenSsids = setOf("", "<hidden>", "unknown", "<Hidden Network>")

    val bySsid = wifiDevices.groupBy { it.name }

    bySsid.forEach { (ssid, group) ->
        if (ssid in hiddenSsids || ssid.isBlank()) return@forEach
        if (group.size < 2) {
            val device = group.first()
            val freq = device.frequency.lowercase()
            val isOpen = !freq.contains("wpa") && !freq.contains("wep") &&
                !device.name.lowercase().contains("wpa") && !device.name.lowercase().contains("wep")
            if (isOpen && device.signalStrength > -50) {
                alerts.add(EvilTwinAlert(
                    ssid = ssid,
                    reason = "Open network with unusually strong signal (${device.signalStrength} dBm) — possible rogue AP",
                    device1Mac = device.macAddress,
                    device2Mac = null,
                    signalStrength = device.signalStrength
                ))
            }
            return@forEach
        }

        val ouiGroups = group.groupBy { device ->
            device.macAddress.uppercase().replace("-", ":").split(":").take(3).joinToString(":")
        }
        if (ouiGroups.size > 1) {
            val d1 = group[0]
            val d2 = group[1]

            // Suppress dual-band router false positives
            if (isSamePhysicalRouter(d1.macAddress, d2.macAddress, d1.signalStrength, d2.signalStrength)) return@forEach

            val oui1 = d1.macAddress.uppercase().replace("-", ":").split(":").take(3).joinToString(":")
            val oui2 = d2.macAddress.uppercase().replace("-", ":").split(":").take(3).joinToString(":")
            alerts.add(EvilTwinAlert(
                ssid = ssid,
                reason = "Duplicate SSID with significantly different manufacturers ($oui1 vs $oui2)",
                device1Mac = d1.macAddress,
                device2Mac = d2.macAddress,
                signalStrength = maxOf(d1.signalStrength, d2.signalStrength)
            ))
        }
    }
    return alerts
}
