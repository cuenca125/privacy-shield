package com.privacyshield.data

data class ScanSessionSummary(
    val scanSessionId: String,
    val timestamp: Long,
    val deviceCount: Int,
    val suspiciousCount: Int
)
