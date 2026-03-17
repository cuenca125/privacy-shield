package com.privacyshield.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.font.FontWeight
import com.privacyshield.OuiLookup
import com.privacyshield.model.AppTheme
import com.privacyshield.model.DetectedDevice
import kotlinx.coroutines.launch

@Composable
fun DeviceDetailScreen(
    device: DetectedDevice,
    currentTheme: AppTheme,
    signalHistory: Map<String, List<Int>>,
    getDeviceColor: (com.privacyshield.model.DeviceType) -> Color,
    getSignalColor: (Int) -> Color,
    getSignalQuality: (Int) -> String,
    getDistanceColor: (Double) -> Color,
    onBack: () -> Unit,
    onMarkSafe: (String) -> Unit,
    onMarkSuspicious: (String) -> Unit,
    onCopyToClipboard: (String, String) -> Unit
) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val context = androidx.compose.ui.platform.LocalContext.current
    var macVendorResult by remember { mutableStateOf<String?>(null) }
    var macVendorLoading by remember { mutableStateOf(false) }
    val detailScope = rememberCoroutineScope()

    BackHandler { onBack() }

    LazyColumn(
        modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding().padding(horizontal = 20.dp)
    ) {
        item {
            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp)) {
                IconButton(
                    onClick = onBack,
                    modifier = Modifier.size(40.dp).clip(CircleShape).background(cardColor)
                ) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = textColor)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Card(
                    modifier = Modifier.size(100.dp),
                    colors = CardDefaults.cardColors(containerColor = cardColor),
                    shape = RoundedCornerShape(20.dp),
                    elevation = CardDefaults.cardElevation(4.dp)
                ) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Icon(device.type.icon, null, tint = getDeviceColor(device.type), modifier = Modifier.size(48.dp))
                    }
                }
                Spacer(modifier = Modifier.height(20.dp))
                Text(device.type.displayName, fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                if (device.name.isNotEmpty()) Text(device.name, fontSize = 14.sp, color = subtextColor)
                if (device.manufacturer != "Unknown") {
                    Text("Made by ${device.manufacturer}", fontSize = 12.sp, color = Color(0xFF4A9EFF), fontWeight = FontWeight.Bold)
                }
            }

            Spacer(modifier = Modifier.height(30.dp))

            DetailRow("Distance", "${device.getDistanceFormatted()} (${device.getDistanceCategory()})", cardColor, textColor, subtextColor, true, onCopyToClipboard)

            // MAC Address row with OUI vendor lookup
            Card(
                modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(12.dp),
                elevation = CardDefaults.cardElevation(2.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("MAC Address", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(device.macAddress, fontSize = 16.sp, color = textColor, fontWeight = FontWeight.Medium)
                        }
                        IconButton(onClick = { onCopyToClipboard("MAC Address", device.macAddress) }, modifier = Modifier.size(36.dp)) {
                            Icon(Icons.Filled.ContentCopy, "Copy", tint = subtextColor, modifier = Modifier.size(20.dp))
                        }
                        if (macVendorLoading) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = Color(0xFF44FF88))
                            Spacer(modifier = Modifier.width(8.dp))
                        } else {
                            IconButton(
                                onClick = {
                                    if (OuiLookup.isRandomizedMac(device.macAddress)) {
                                        macVendorResult = "RANDOMIZED"
                                    } else {
                                        macVendorLoading = true
                                        detailScope.launch {
                                            val result = OuiLookup.lookupWithFallback(context, device.macAddress)
                                            macVendorResult = when {
                                                result == "Randomized MAC — vendor unknown" -> "RANDOMIZED"
                                                result == "Unknown vendor" -> "NOT_FOUND"
                                                else -> result
                                            }
                                            macVendorLoading = false
                                        }
                                    }
                                },
                                modifier = Modifier.size(36.dp)
                            ) {
                                Icon(Icons.Filled.Search, "Lookup vendor", tint = subtextColor, modifier = Modifier.size(20.dp))
                            }
                        }
                    }
                    macVendorResult?.let { result ->
                        Spacer(modifier = Modifier.height(6.dp))
                        val vendorSuccessColor = if (currentTheme == AppTheme.DARK) Color(0xFF44FF88) else Color(0xFF2E7D32)
                        when {
                            result == "RANDOMIZED" -> Text("Randomized MAC — vendor lookup unavailable",
                                fontSize = 12.sp, color = subtextColor, fontWeight = FontWeight.Normal)
                            result == "NOT_FOUND" -> Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Vendor unknown", fontSize = 12.sp, color = subtextColor)
                            }
                            result == "ERROR" -> Text("Lookup failed", fontSize = 12.sp, color = Color(0xFFFFAA44))
                            else -> Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.Verified, null, tint = vendorSuccessColor, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Vendor: $result", fontSize = 12.sp, color = vendorSuccessColor, fontWeight = FontWeight.Medium)
                            }
                        }
                    }
                }
            }

            if (device.manufacturer != "Unknown") {
                DetailRow("Manufacturer", device.manufacturer, cardColor, textColor, subtextColor, true, onCopyToClipboard)
            }
            DetailRow("Signal Strength", "${device.signalStrength} dBm (${getSignalQuality(device.signalStrength)})", cardColor, textColor, subtextColor, true, onCopyToClipboard)
            if (device.protocol.isNotEmpty()) DetailRow("Protocol", device.protocol, cardColor, textColor, subtextColor, true, onCopyToClipboard)
            if (device.frequency.isNotEmpty()) DetailRow("Frequency", device.frequency, cardColor, textColor, subtextColor, true, onCopyToClipboard)
            DetailRow("Status", if (device.isSuspicious()) "⚠️ Suspicious" else "✓ Normal", cardColor, textColor, subtextColor, false, onCopyToClipboard)
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { onMarkSafe(device.macAddress) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF44FF88))
                ) {
                    Icon(Icons.Filled.CheckCircle, null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Mark Safe", fontSize = 13.sp)
                }
                OutlinedButton(
                    onClick = { onMarkSuspicious(device.macAddress) },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFFF4444))
                ) {
                    Icon(Icons.Filled.Warning, null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Mark Suspicious", fontSize = 13.sp)
                }
            }
            val history = signalHistory[device.macAddress] ?: emptyList()
            if (history.size >= 3) {
                Spacer(modifier = Modifier.height(16.dp))
                Text("SIGNAL HISTORY", fontSize = 11.sp, fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                Spacer(modifier = Modifier.height(8.dp))
                val graphColor = getDeviceColor(device.type)
                Canvas(
                    modifier = Modifier.fillMaxWidth().height(80.dp).clip(RoundedCornerShape(8.dp)).background(cardColor)
                ) {
                    val minDb = -100f
                    val maxDb = -30f
                    val range = maxDb - minDb
                    val w = size.width
                    val h = size.height
                    val stepX = w / (history.size - 1).toFloat()
                    val points = history.mapIndexed { i, db ->
                        val x = i * stepX
                        val y = h - ((db - minDb) / range * h).coerceIn(0f, h)
                        Offset(x, y)
                    }
                    val path = Path()
                    path.moveTo(points.first().x, h)
                    points.forEach { path.lineTo(it.x, it.y) }
                    path.lineTo(points.last().x, h)
                    path.close()
                    drawPath(path, graphColor.copy(alpha = 0.2f))
                    for (i in 0 until points.size - 1) {
                        drawLine(graphColor, points[i], points[i + 1], strokeWidth = 2.dp.toPx())
                    }
                    val paint = android.graphics.Paint().apply {
                        color = 0xFF888888.toInt()
                        textSize = 9.sp.toPx()
                        isAntiAlias = true
                    }
                    drawIntoCanvas { canvas ->
                        canvas.nativeCanvas.drawText("${history.min()} dBm", 4f, h - 4f, paint)
                        canvas.nativeCanvas.drawText("${history.max()} dBm", 4f, 14f, paint)
                    }
                }
            }
        }
    }
}

@Composable
fun DetailRow(
    label: String,
    value: String,
    cardColor: Color,
    textColor: Color,
    subtextColor: Color,
    canCopy: Boolean,
    onCopyToClipboard: (String, String) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        colors = CardDefaults.cardColors(containerColor = cardColor),
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(2.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(label, fontSize = 11.sp, fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                Spacer(modifier = Modifier.height(4.dp))
                Text(value, fontSize = 16.sp, color = textColor, fontWeight = FontWeight.Medium)
            }
            if (canCopy) {
                IconButton(onClick = { onCopyToClipboard(label, value) }, modifier = Modifier.size(36.dp)) {
                    Icon(Icons.Filled.ContentCopy, "Copy", tint = subtextColor, modifier = Modifier.size(20.dp))
                }
            }
        }
    }
}
