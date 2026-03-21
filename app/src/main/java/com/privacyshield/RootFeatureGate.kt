package com.privacyshield

object RootFeatureGate {
    val enabled: Boolean get() = BuildConfig.ENABLE_ROOT_FEATURES

    // SECURITY FIX (public build): Shell execution removed. isRooted() is dead code in the
    // public release (ENABLE_ROOT_FEATURES=false); stub preserved for API compatibility.
    fun isRooted(): Boolean = false

    fun canUseRootFeatures(): Boolean {
        // If root features explicitly enabled via BuildConfig, trust it
        // (used for dev builds and emulator testing)
        if (BuildConfig.ENABLE_ROOT_FEATURES) return true
        return false
    }
}
