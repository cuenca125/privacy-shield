package com.privacyshield

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL

object OuiLookup {

    // In-memory cache: OUI prefix (6 hex chars uppercase) → vendor name
    private val localDb = mutableMapOf<String, String>()
    private val apiCache = mutableMapOf<String, String>()
    private var dbLoaded = false

    fun loadDatabase(context: Context) {
        if (dbLoaded) return
        try {
            context.assets.open("oui_database.txt").bufferedReader().forEachLine { line ->
                val parts = line.trim().split("\t")
                if (parts.size >= 2) {
                    localDb[parts[0].uppercase()] = parts[1]
                }
            }
            dbLoaded = true
        } catch (e: Exception) {
            dbLoaded = true // Don't retry on failure
        }
    }

    fun extractOui(mac: String): String {
        return mac.uppercase().replace(":", "").replace("-", "").take(6)
    }

    fun isRandomizedMac(mac: String): Boolean {
        val normalized = mac.uppercase().replace(":", "").replace("-", "")
        if (normalized.length < 2) return false
        val firstOctet = normalized.substring(0, 2).toIntOrNull(16) ?: return false
        // Locally administered bit: second-least-significant bit of first octet
        return (firstOctet and 0x02) != 0
    }

    fun lookupLocal(mac: String): String? {
        if (isRandomizedMac(mac)) return "Randomized MAC"
        val oui = extractOui(mac)
        return localDb[oui]
    }

    suspend fun lookupWithFallback(context: Context, mac: String): String {
        if (!dbLoaded) loadDatabase(context)

        if (isRandomizedMac(mac)) return "Randomized MAC — vendor unknown"

        val oui = extractOui(mac)

        localDb[oui]?.let { return it }

        apiCache[oui]?.let { return it }

        return withContext(Dispatchers.IO) {
            try {
                val formattedOui = "${oui.substring(0,2)}:${oui.substring(2,4)}:${oui.substring(4,6)}"
                val url = "https://api.macvendors.com/$formattedOui"
                val connection = URL(url).openConnection()
                connection.connectTimeout = 3000
                connection.readTimeout = 3000
                val response = connection.getInputStream().bufferedReader().readText().trim()
                if (response.isNotEmpty() && !response.contains("errors") && response.length < 100) {
                    apiCache[oui] = response
                    response
                } else {
                    apiCache[oui] = "Unknown vendor"
                    "Unknown vendor"
                }
            } catch (e: Exception) {
                "Unknown vendor"
            }
        }
    }
}
