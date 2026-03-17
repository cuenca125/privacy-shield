package com.privacyshield

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.privacyshield.data.AppDatabase
import com.privacyshield.data.DeviceHistoryEntity
import com.privacyshield.model.DetectedDevice
import com.privacyshield.model.DeviceType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

class ScanWorker(
    private val context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {

    companion object {
        const val CHANNEL_ID = "privacy_alerts"
        const val WORK_NAME = "privacy_shield_background_scan"
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            val database = AppDatabase.getInstance(context)
            val lastTs = database.deviceHistoryDao().getLastSessionTimestamp() ?: 0L
            if (System.currentTimeMillis() - lastTs < 120_000L) return@withContext Result.success()

            val wifiManager = context.applicationContext
                .getSystemService(Context.WIFI_SERVICE) as WifiManager
            val scanResults = wifiManager.scanResults
            if (scanResults.isNullOrEmpty()) return@withContext Result.success()

            val sessionId = UUID.randomUUID().toString()
            val timestamp = System.currentTimeMillis()

            val entities = scanResults.map { result ->
                val ssid = result.SSID?.takeIf { it.isNotEmpty() } ?: "<Hidden Network>"
                val isSuspicious = result.SSID.isNullOrEmpty() || result.level < -80
                DeviceHistoryEntity(
                    name = ssid,
                    deviceType = "WiFi",
                    macAddress = result.BSSID ?: "00:00:00:00:00:00",
                    signalStrength = result.level,
                    protocol = "WiFi",
                    frequency = "${result.frequency} MHz",
                    manufacturer = "Unknown",
                    isSuspicious = isSuspicious,
                    scanSessionId = sessionId,
                    timestamp = timestamp
                )
            }

            database.deviceHistoryDao().insertAll(entities)

            val suspiciousCount = entities.count { it.isSuspicious }
            if (suspiciousCount > 0) {
                sendNotification(suspiciousCount)
            }

            // Evil twin detection
            val detectedDevices = entities.map { e ->
                DetectedDevice(
                    name = e.name,
                    type = DeviceType.ROUTER,
                    macAddress = e.macAddress,
                    signalStrength = e.signalStrength,
                    protocol = e.protocol,
                    frequency = e.frequency,
                    manufacturer = e.manufacturer
                )
            }
            val evilTwins = detectEvilTwins(detectedDevices)
            if (evilTwins.isNotEmpty()) {
                sendEvilTwinNotification(evilTwins.first().ssid)
            }

            Result.success()
        } catch (e: Exception) {
            Result.failure()
        }
    }

    private fun sendNotification(suspiciousCount: Int) {
        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Privacy Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts for suspicious devices detected during background scans"
            }
            notificationManager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Privacy Shield Alert")
            .setContentText("$suspiciousCount suspicious device(s) detected in background scan")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(1001, notification)
    }

    private fun sendEvilTwinNotification(ssid: String) {
        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Privacy Alerts", NotificationManager.IMPORTANCE_HIGH
            ).apply { description = "Alerts for suspicious devices detected during background scans" }
            notificationManager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Evil Twin Detected")
            .setContentText("Rogue AP suspected: $ssid. Do not connect.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(1002, notification)
    }
}
