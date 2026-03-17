package com.privacyshield.model

import androidx.compose.runtime.Stable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import kotlin.math.pow

@Stable
data class DetectedDevice(
    val name: String,
    val type: DeviceType,
    val macAddress: String,
    var signalStrength: Int,
    val protocol: String,
    val frequency: String = "",
    val manufacturer: String = "Unknown",
    val id: String = macAddress
) {
    fun getDistance(): Double {
        val freq = if (protocol == "WiFi" && frequency.isNotEmpty()) {
            frequency.replace(" MHz", "").toDoubleOrNull() ?: 2400.0
        } else 2400.0

        val fspl = 27.55 - (20 * kotlin.math.log10(freq)) + Math.abs(signalStrength.toDouble())
        return 10.0.pow(fspl / 20.0)
    }

    fun getDistanceCategory(): String = when {
        getDistance() < 5 -> "Near"
        getDistance() < 15 -> "Medium"
        else -> "Far"
    }

    fun getDistanceFormatted(): String {
        val distance = getDistance()
        return when {
            distance < 1 -> "<1m"
            distance < 10 -> "${distance.toInt()}m"
            else -> "${(distance / 10).toInt() * 10}m+"
        }
    }

    fun isSuspicious(): Boolean = when (type) {
        DeviceType.CAMERA, DeviceType.MICROPHONE -> true
        DeviceType.ROUTER -> false
        DeviceType.UNKNOWN -> manufacturer == "Unknown"
        else -> false
    }

    fun isVeryClose(): Boolean = getDistance() < 3
}

data class PortScanResult(val ip: String, val timestamp: Long, val openPorts: List<Int>)
data class TraceHop(val hop: Int, val ip: String, val ms: Long, val timedOut: Boolean)

@Stable
data class CveResult(
    val id: String,
    val summary: String,
    val cvss: Double?,
    val published: String,
    val references: List<String>,
    val source: String = "CIRCL"
)

@Stable
data class EvilTwinAlert(
    val ssid: String,
    val reason: String,
    val device1Mac: String,
    val device2Mac: String?,
    val signalStrength: Int
)

@Stable
data class SecurityFeatureInfo(
    val id: String,
    val name: String,
    val description: String,
    val icon: ImageVector,
    val fullDescription: String
)

// SECURITY FIX: Validates that a network target is a well-formed IPv4, IPv6, CIDR, or hostname.
// Prevents arbitrary/malformed strings from being passed to socket APIs or embedded in URLs.
fun isValidNetworkTarget(input: String): Boolean {
    val s = input.trim()
    if (s.isEmpty()) return false
    // IPv4 (with optional CIDR suffix)
    val ipv4Cidr = Regex("""^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$""")
    if (ipv4Cidr.matches(s)) {
        val ipPart = s.substringBefore("/")
        return ipPart.split(".").all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
    }
    // IPv6
    val ipv6 = Regex("""^[0-9a-fA-F:]{2,39}$""")
    if (ipv6.matches(s)) return true
    // Hostname: labels of alphanumeric + hyphens, separated by dots, max 253 chars
    val hostname = Regex("""^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$""")
    return hostname.matches(s) && s.length <= 253
}

fun getCveSeverity(cvss: Double?): Pair<String, Color> = when {
    cvss == null -> "UNKNOWN" to Color(0xFF888888)
    cvss >= 9.0 -> "CRITICAL" to Color(0xFFFF4444)
    cvss >= 7.0 -> "HIGH" to Color(0xFFFF8844)
    cvss >= 4.0 -> "MEDIUM" to Color(0xFFE6A817)
    else -> "LOW" to Color(0xFF44BB77)
}
