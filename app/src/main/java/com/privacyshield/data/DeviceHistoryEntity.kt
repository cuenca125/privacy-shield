package com.privacyshield.data

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.privacyshield.DetectedDevice

@Entity(tableName = "device_history")
data class DeviceHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    val deviceType: String,
    val macAddress: String,
    val signalStrength: Int,
    val protocol: String,
    val frequency: String,
    val manufacturer: String,
    val isSuspicious: Boolean,
    val scanSessionId: String,
    val timestamp: Long,
    val userMarkedSafe: Boolean = false,
    val userMarkedSuspicious: Boolean = false
)

fun DetectedDevice.toHistoryEntity(sessionId: String, timestamp: Long): DeviceHistoryEntity =
    DeviceHistoryEntity(
        name = name,
        deviceType = type.name,
        macAddress = macAddress,
        signalStrength = signalStrength,
        protocol = protocol,
        frequency = frequency,
        manufacturer = manufacturer,
        isSuspicious = isSuspicious(),
        scanSessionId = sessionId,
        timestamp = timestamp
    )
