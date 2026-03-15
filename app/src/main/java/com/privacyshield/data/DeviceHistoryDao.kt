package com.privacyshield.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query

@Dao
interface DeviceHistoryDao {

    @Insert
    suspend fun insertAll(devices: List<DeviceHistoryEntity>)

    @Query("""
        SELECT scanSessionId, MIN(timestamp) as timestamp,
               COUNT(*) as deviceCount,
               SUM(CASE WHEN isSuspicious = 1 THEN 1 ELSE 0 END) as suspiciousCount
        FROM device_history
        GROUP BY scanSessionId
        ORDER BY timestamp DESC
    """)
    suspend fun getAllSessions(): List<ScanSessionSummary>

    @Query("SELECT * FROM device_history WHERE scanSessionId = :sessionId ORDER BY isSuspicious DESC, signalStrength DESC")
    suspend fun getDevicesForSession(sessionId: String): List<DeviceHistoryEntity>

    @Query("DELETE FROM device_history WHERE scanSessionId = :sessionId")
    suspend fun deleteSession(sessionId: String)

    @Query("DELETE FROM device_history")
    suspend fun clearAll()

    @Query("SELECT * FROM device_history ORDER BY timestamp DESC")
    suspend fun getAllDevices(): List<DeviceHistoryEntity>

    @Query("UPDATE device_history SET userMarkedSafe = :safe, userMarkedSuspicious = :suspicious WHERE macAddress = :mac")
    suspend fun updateUserMark(mac: String, safe: Boolean, suspicious: Boolean)

    @Query("SELECT MIN(timestamp) FROM device_history WHERE scanSessionId = (SELECT scanSessionId FROM device_history ORDER BY timestamp DESC LIMIT 1)")
    suspend fun getLastSessionTimestamp(): Long?

    @Query("DELETE FROM device_history WHERE timestamp < :cutoffTimestamp")
    suspend fun deleteOlderThan(cutoffTimestamp: Long)
}
