package com.privacyshield

object RootFeatureGate {
    val enabled: Boolean get() = BuildConfig.ENABLE_ROOT_FEATURES

    fun isRooted(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val result = process.inputStream.bufferedReader().readLine() ?: ""
            result.contains("uid=0")
        } catch (e: Exception) {
            false
        }
    }

    fun canUseRootFeatures(): Boolean = enabled && isRooted()
}
