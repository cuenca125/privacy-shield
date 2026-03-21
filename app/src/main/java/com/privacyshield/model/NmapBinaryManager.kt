package com.privacyshield.model

import android.content.Context
import android.os.Build
import com.privacyshield.BuildConfig
import java.io.File

object NmapBinaryManager {
    private var extractedPath: String? = null

    private fun assetNameForAbi(): String? {
        val supportedAbis = Build.SUPPORTED_ABIS
        return when {
            supportedAbis.contains("arm64-v8a") -> "nmap_arm64"
            supportedAbis.contains("x86_64") -> "nmap_x86_64"
            else -> null
        }
    }

    fun getNmapPath(context: Context): String? {
        if (!BuildConfig.ENABLE_ROOT_FEATURES) return null

        extractedPath?.let { if (File(it).canExecute()) return it }

        val assetName = assetNameForAbi() ?: return null
        val outFile = File(context.filesDir, "nmap")
        return try {
            context.assets.open(assetName).use { input ->
                outFile.outputStream().use { output -> input.copyTo(output) }
            }
            outFile.setExecutable(true, false)
            extractedPath = outFile.absolutePath
            outFile.absolutePath
        } catch (e: Exception) {
            null
        }
    }

    fun isAvailable(context: Context): Boolean = getNmapPath(context) != null
}
