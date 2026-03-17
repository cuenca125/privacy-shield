package com.privacyshield.ui

import android.net.wifi.WifiManager
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.privacyshield.model.AppTheme
import com.privacyshield.model.DetectedDevice
import com.privacyshield.model.EvilTwinAlert
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun NetworkTab(
    currentTheme: AppTheme,
    devices: List<DetectedDevice>,
    wifiManager: WifiManager,
    historyResetTrigger: Int,
    onEvilTwinAlertsUpdated: (List<EvilTwinAlert>) -> Unit
) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    fun intToIp(ip: Int): String = "%d.%d.%d.%d".format(
        ip and 0xff, ip shr 8 and 0xff, ip shr 16 and 0xff, ip shr 24 and 0xff)

    var gatewayIp by remember { mutableStateOf("") }
    var gatewayHostname by remember { mutableStateOf("") }
    var subnetMask by remember { mutableStateOf("") }
    var dns1 by remember { mutableStateOf("") }
    var dns2 by remember { mutableStateOf("") }
    var dhcpServer by remember { mutableStateOf("") }
    var isHostScanning by remember { mutableStateOf(false) }
    var scanProgress by remember { mutableStateOf(0f) }
    var discoveredHosts by remember { mutableStateOf<List<Triple<String, Long, String>>>(emptyList()) }
    var dnsResult by remember { mutableStateOf("") }
    var isDnsChecking by remember { mutableStateOf(false) }
    var gatewayPingResult by remember { mutableStateOf("") }
    var isGatewayPinging by remember { mutableStateOf(false) }
    // Security checks
    data class SecurityCheck(val name: String, val result: String, val level: Int) // 0=pass,1=info,2=warn
    var securityChecks by remember { mutableStateOf<List<SecurityCheck>>(emptyList()) }
    var evilTwinAlerts by remember { mutableStateOf<List<EvilTwinAlert>>(emptyList()) }
    var evilTwinExpanded by remember { mutableStateOf(false) }

    LaunchedEffect(currentTheme) {
        val dhcpInfo = withContext(Dispatchers.IO) { wifiManager.dhcpInfo }
        if (dhcpInfo != null) {
            gatewayIp = intToIp(dhcpInfo.gateway)
            subnetMask = intToIp(dhcpInfo.netmask)
            dns1 = intToIp(dhcpInfo.dns1)
            dns2 = intToIp(dhcpInfo.dns2)
            dhcpServer = intToIp(dhcpInfo.serverAddress)
            // Resolve gateway hostname
            if (gatewayIp.isNotEmpty() && gatewayIp != "0.0.0.0") {
                gatewayHostname = withContext(Dispatchers.IO) {
                    try {
                        withTimeoutOrNull(1000) {
                            val h = InetAddress.getByName(gatewayIp).canonicalHostName
                            if (h != gatewayIp) h else ""
                        } ?: ""
                    } catch (e: Exception) { "" }
                }
            }
        }
        // Run security checks
        @Suppress("DEPRECATION")
        val wifiInfo = wifiManager.connectionInfo
        val checks = mutableListOf<SecurityCheck>()
        if (wifiInfo != null && wifiInfo.networkId != -1) {
            checks.add(SecurityCheck("Open WiFi", "Connected to a network", 1))
        } else {
            checks.add(SecurityCheck("Open WiFi", "Not connected", 2))
        }
        val dnsIp = if (dns1.isNotEmpty() && dns1 != "0.0.0.0") dns1 else ""
        val isPrivateDns = dnsIp.startsWith("8.8.") || dnsIp.startsWith("1.1.") ||
            dnsIp.startsWith("9.9.9.") || dnsIp.startsWith("208.67.")
        checks.add(if (isPrivateDns)
            SecurityCheck("DNS Security", "Using trusted public DNS ($dnsIp)", 0)
        else
            SecurityCheck("DNS Security", "Consider using private DNS (1.1.1.1)", 2))
        if (gatewayIp.isNotEmpty() && gatewayIp != "0.0.0.0") {
            val reachable = withContext(Dispatchers.IO) {
                try { InetAddress.getByName(gatewayIp).isReachable(1000) } catch (e: Exception) { false }
            }
            checks.add(SecurityCheck("Gateway Exposure",
                if (reachable) "Gateway $gatewayIp is reachable" else "Gateway not reachable", 1))
        }
        val ipInt = wifiInfo?.ipAddress ?: 0
        val ipAddr = if (ipInt != 0) "%d.%d.%d.%d".format(
            ipInt and 0xff, ipInt shr 8 and 0xff, ipInt shr 16 and 0xff, ipInt shr 24 and 0xff) else ""
        val isPrivateIp = ipAddr.startsWith("192.168.") || ipAddr.startsWith("10.")
        checks.add(if (isPrivateIp)
            SecurityCheck("IP Privacy", "Using private IP range ($ipAddr)", 0)
        else
            SecurityCheck("IP Privacy", if (ipAddr.isEmpty()) "Not connected" else "Public IP detected", 2))
        securityChecks = checks

        val detectedAlerts = com.privacyshield.detectEvilTwins(devices)
        evilTwinAlerts = detectedAlerts
        onEvilTwinAlertsUpdated(detectedAlerts)
    }

    val listState = rememberLazyListState()
    LaunchedEffect(historyResetTrigger) {
        if (historyResetTrigger > 0) listState.animateScrollToItem(0)
    }

    LazyColumn(
        state = listState,
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()
    ) {
        item {
            Text("NETWORK ANALYSIS", fontSize = 22.sp, fontWeight = FontWeight.Bold,
                color = textColor, letterSpacing = 2.sp)
        }

        // Connected Network card
        item {
            @Suppress("DEPRECATION")
            val wifiInfo = wifiManager.connectionInfo
            if (wifiInfo != null && wifiInfo.networkId != -1) {
                val rawSsid = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    wifiInfo.ssid?.removePrefix("\"")?.removeSuffix("\"") ?: "Unknown"
                } else {
                    @Suppress("DEPRECATION") wifiInfo.ssid?.removePrefix("\"")?.removeSuffix("\"") ?: "Unknown"
                }
                val ipInt = wifiInfo.ipAddress
                val ipAddress = "%d.%d.%d.%d".format(
                    ipInt and 0xff, ipInt shr 8 and 0xff, ipInt shr 16 and 0xff, ipInt shr 24 and 0xff)
                Card(modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = cardColor),
                    shape = RoundedCornerShape(16.dp),
                    elevation = CardDefaults.cardElevation(4.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("CONNECTED NETWORK", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Column {
                                Text(rawSsid, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = textColor)
                                Text(ipAddress, fontSize = 12.sp, color = subtextColor)
                            }
                            Column(horizontalAlignment = Alignment.End) {
                                val rssi = wifiInfo.rssi
                                val signalLabel = when {
                                    rssi > -50 -> "Excellent"
                                    rssi > -60 -> "Good"
                                    rssi > -70 -> "Fair"
                                    else -> "Poor"
                                }
                                val signalColor = when {
                                    rssi > -50 -> Color(0xFF44BB77)
                                    rssi > -60 -> Color(0xFF88CC44)
                                    rssi > -70 -> Color(0xFFFF8844)
                                    else -> Color(0xFFFF4444)
                                }
                                Row(verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text("${wifiInfo.linkSpeed} Mbps", fontSize = 14.sp, color = Color(0xFF44FF88), fontWeight = FontWeight.Medium)
                                    Text("·", fontSize = 12.sp, color = subtextColor)
                                    Text(signalLabel, fontSize = 12.sp, color = signalColor, fontWeight = FontWeight.Medium)
                                }
                                Text("${wifiInfo.frequency} MHz · ${rssi} dBm", fontSize = 12.sp, color = subtextColor)
                            }
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("Note: Speed shown is link rate, not internet speed",
                            fontSize = 11.sp, color = subtextColor,
                            fontStyle = FontStyle.Italic)
                    }
                }
            }
        }

        // Section 1 - Gateway Info
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("GATEWAY INFO", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(12.dp))
                    if (gatewayIp.isEmpty() || gatewayIp == "0.0.0.0") {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.WifiOff, null, tint = subtextColor, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Not connected to WiFi", color = subtextColor, fontSize = 13.sp)
                        }
                    } else {
                        val clipboard = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        if (gatewayHostname.isNotEmpty()) {
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Gateway Host", fontSize = 13.sp, color = subtextColor)
                                Text(gatewayHostname, fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                            }
                        }
                        listOf("Gateway" to gatewayIp, "Subnet Mask" to subnetMask,
                            "DNS 1" to dns1, "DNS 2" to dns2, "DHCP Server" to dhcpServer
                        ).filter { it.second.isNotEmpty() && it.second != "0.0.0.0" }
                        .forEach { (label, value) ->
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(label, fontSize = 13.sp, color = subtextColor)
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(value, fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Icon(Icons.Filled.ContentCopy, null,
                                        modifier = Modifier.size(16.dp).clickable {
                                            clipboard.setPrimaryClip(android.content.ClipData.newPlainText(label, value))
                                            Toast.makeText(context, "$label copied", Toast.LENGTH_SHORT).show()
                                        }, tint = subtextColor)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Section 2 - Host Discovery
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("HOST DISCOVERY", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    if (gatewayIp.isNotEmpty() && gatewayIp != "0.0.0.0") {
                        OutlinedButton(
                            onClick = {
                                if (!isGatewayPinging) {
                                    isGatewayPinging = true
                                    gatewayPingResult = ""
                                    scope.launch {
                                        val start = System.currentTimeMillis()
                                        val reachable = try {
                                            withContext(Dispatchers.IO) { InetAddress.getByName(gatewayIp).isReachable(2000) }
                                        } catch (e: Exception) { false }
                                        val elapsed = System.currentTimeMillis() - start
                                        gatewayPingResult = if (reachable) "Gateway ${gatewayIp}: ${elapsed}ms" else "Gateway ${gatewayIp}: unreachable"
                                        isGatewayPinging = false
                                    }
                                }
                            },
                            enabled = !isGatewayPinging,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            if (isGatewayPinging) {
                                CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                                Spacer(modifier = Modifier.width(6.dp))
                            }
                            Text("Quick Ping Gateway ($gatewayIp)", fontSize = 13.sp)
                        }
                        if (gatewayPingResult.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(gatewayPingResult, fontSize = 12.sp,
                                color = if (gatewayPingResult.contains("unreachable")) Color(0xFFFF4444) else Color(0xFF44BB77))
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                    Button(
                        onClick = {
                            if (!isHostScanning) {
                                isHostScanning = true
                                discoveredHosts = emptyList()
                                scanProgress = 0f
                                scope.launch {
                                    val dhcpInfo = withContext(Dispatchers.IO) { wifiManager.dhcpInfo }
                                    val gatewayInt = dhcpInfo?.gateway ?: 0
                                    if (gatewayInt == 0) { isHostScanning = false; return@launch }
                                    val base = intToIp(gatewayInt).substringBeforeLast(".")
                                    val found = mutableListOf<Triple<String, Long, String>>()
                                    var done = 0
                                    (1..254).chunked(20).forEach { batch ->
                                        val batchResults = withContext(Dispatchers.IO) {
                                            coroutineScope {
                                                batch.map { i ->
                                                    async {
                                                        val ip = "$base.$i"
                                                        val start = System.currentTimeMillis()
                                                        val reachable = try { InetAddress.getByName(ip).isReachable(300) } catch (e: Exception) { false }
                                                        val elapsed = System.currentTimeMillis() - start
                                                        val hostname = if (reachable) {
                                                            try {
                                                                withTimeoutOrNull(500) {
                                                                    val h = InetAddress.getByName(ip).canonicalHostName
                                                                    if (h != ip) h else ""
                                                                } ?: ""
                                                            } catch (e: Exception) { "" }
                                                        } else ""
                                                        Triple(ip, reachable to elapsed, hostname)
                                                    }
                                                }.awaitAll()
                                            }
                                        }
                                        done += batch.size
                                        batchResults.filter { it.second.first }.forEach { (ip, pair, hostname) ->
                                            found.add(Triple(ip, pair.second, hostname))
                                        }
                                        scanProgress = done.toFloat() / 254f
                                        discoveredHosts = found.sortedBy { it.second }
                                    }
                                    isHostScanning = false
                                    scanProgress = 1f
                                }
                            }
                        },
                        enabled = !isHostScanning,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        if (isHostScanning) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = Color.White, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Scanning... ${(scanProgress * 100).toInt()}%", color = Color.White)
                        } else {
                            Text("Scan Local Network", color = Color.White)
                        }
                    }
                    if (isHostScanning) {
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(
                            progress = { scanProgress },
                            modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)),
                            color = Color(0xFF44FF88),
                            trackColor = subtextColor.copy(alpha = 0.2f)
                        )
                    }
                    if (discoveredHosts.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        val subnet = gatewayIp.substringBeforeLast(".")
                        Row(modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("${discoveredHosts.size} host${if (discoveredHosts.size > 1) "s" else ""} found on $subnet.0/24",
                                fontSize = 12.sp, color = subtextColor)
                            TextButton(onClick = {
                                val ts = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())
                                val report = buildString {
                                    appendLine("Host Discovery - $subnet.0/24")
                                    appendLine(ts)
                                    appendLine()
                                    appendLine("Active Hosts:")
                                    discoveredHosts.forEach { (ip, ms, hostname) ->
                                        appendLine("$ip - ${ms}ms${if (hostname.isNotEmpty()) " - $hostname" else ""}")
                                    }
                                }
                                val shareIntent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(android.content.Intent.EXTRA_TEXT, report)
                                    putExtra(android.content.Intent.EXTRA_SUBJECT, "Host Discovery Results")
                                }
                                context.startActivity(android.content.Intent.createChooser(shareIntent, "Export Results"))
                            }) { Text("Export", fontSize = 11.sp, color = Color(0xFF44FF88)) }
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        discoveredHosts.forEach { (ip, elapsed, hostname) ->
                            val msColor = when {
                                elapsed < 50 -> Color(0xFF44BB77)
                                elapsed < 200 -> Color(0xFFFF8844)
                                else -> Color(0xFFFF4444)
                            }
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(ip, fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                                    if (hostname.isNotEmpty()) {
                                        Text(hostname, fontSize = 11.sp, color = subtextColor)
                                    }
                                }
                                Row(verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text("${elapsed}ms", fontSize = 13.sp, color = msColor)
                                    Icon(Icons.Filled.ContentCopy, null,
                                        modifier = Modifier.size(14.dp).clickable {
                                            val cb = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                            cb.setPrimaryClip(android.content.ClipData.newPlainText("IP", ip))
                                            Toast.makeText(context, "$ip copied", Toast.LENGTH_SHORT).show()
                                        }, tint = subtextColor)
                                }
                            }
                        }
                    } else if (!isHostScanning) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.NetworkCheck, null, tint = subtextColor, modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Tap to analyze your network", color = subtextColor, fontSize = 13.sp)
                        }
                    }
                }
            }
        }

        // Section 3 - DNS Check
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("DNS LEAK CHECK", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = {
                            if (!isDnsChecking) {
                                isDnsChecking = true
                                dnsResult = ""
                                scope.launch {
                                    try {
                                        val ip = withContext(Dispatchers.IO) {
                                            InetAddress.getByName("whoami.akamai.net").hostAddress ?: ""
                                        }
                                        dnsResult = ip
                                    } catch (e: Exception) {
                                        dnsResult = "ERROR: ${e.message}"
                                    }
                                    isDnsChecking = false
                                }
                            }
                        },
                        enabled = !isDnsChecking,
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        if (isDnsChecking) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = Color.White, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Checking...", color = Color.White)
                        } else {
                            Text("Check DNS", color = Color.White)
                        }
                    }
                    if (dnsResult.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        if (dnsResult.startsWith("ERROR:")) {
                            Text(dnsResult, fontSize = 13.sp, color = Color(0xFFFF4444))
                        } else {
                            val provider = when {
                                dnsResult.startsWith("8.8.") -> "Google"
                                dnsResult.startsWith("1.1.") -> "Cloudflare"
                                dnsResult.startsWith("9.9.9.") -> "Quad9"
                                dnsResult.startsWith("208.67.") -> "OpenDNS"
                                else -> "ISP/Unknown"
                            }
                            val isSecure = provider != "ISP/Unknown"
                            val recommendation = if (isSecure)
                                "Your connection uses a trusted public DNS resolver."
                            else
                                "Consider switching to a privacy-focused DNS (1.1.1.1 or 8.8.8.8)."
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                                horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("DNS Server", fontSize = 12.sp, color = subtextColor)
                                Text(dnsResult, fontSize = 12.sp, color = textColor, fontWeight = FontWeight.Medium)
                            }
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                                horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Provider", fontSize = 12.sp, color = subtextColor)
                                Text(provider, fontSize = 12.sp, color = textColor, fontWeight = FontWeight.Medium)
                            }
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically) {
                                Text("Status", fontSize = 12.sp, color = subtextColor)
                                Text(
                                    if (isSecure) "SECURE" else "ISP DNS",
                                    fontSize = 12.sp,
                                    color = if (isSecure) Color(0xFF44BB77) else Color(0xFFFF8844),
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(recommendation, fontSize = 12.sp, color = subtextColor)
                            Spacer(modifier = Modifier.height(8.dp))
                            val (recCardColor, recCardTextColor, recCardText) = when {
                                provider == "Cloudflare" || provider == "Quad9" ->
                                    Triple(Color(0xFF1B3A2A), Color(0xFF44BB77), "Good choice \u2014 using privacy-focused DNS")
                                provider == "Google" ->
                                    Triple(Color(0xFF1A2B3A), Color(0xFF4A9EFF), "Using Google DNS \u2014 consider Cloudflare 1.1.1.1 for more privacy")
                                else ->
                                    Triple(Color(0xFF2A2A1A), Color(0xFFBBBB44), "Consider switching to 1.1.1.1 (Cloudflare) for privacy")
                            }
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(containerColor = recCardColor),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Row(modifier = Modifier.padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Filled.Info, null, tint = recCardTextColor, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(recCardText, fontSize = 12.sp, color = recCardTextColor)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Section 4 - Security Analysis
        if (securityChecks.isNotEmpty()) {
            item {
                Card(modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = cardColor),
                    shape = RoundedCornerShape(16.dp),
                    elevation = CardDefaults.cardElevation(4.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("SECURITY ANALYSIS", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        securityChecks.forEach { check ->
                            val (icon, iconColor) = when (check.level) {
                                0 -> Icons.Filled.CheckCircle to Color(0xFF44BB77)
                                1 -> Icons.Filled.Info to Color(0xFF4488FF)
                                else -> Icons.Filled.Warning to Color(0xFFFF8844)
                            }
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(icon, null, tint = iconColor, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text(check.name, fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                                    Text(check.result, fontSize = 11.sp, color = subtextColor)
                                }
                            }
                        }
                        // Evil Twin Detection row
                        Spacer(modifier = Modifier.height(4.dp))
                        Divider(color = subtextColor.copy(alpha = 0.15f))
                        Spacer(modifier = Modifier.height(4.dp))
                        val wifiDevicesForEt = devices.filter { it.protocol == "WiFi" }
                        val etIcon = when {
                            wifiDevicesForEt.isEmpty() -> Icons.Filled.Shield
                            evilTwinAlerts.isEmpty() -> Icons.Filled.CheckCircle
                            else -> Icons.Filled.Warning
                        }
                        val etColor = when {
                            wifiDevicesForEt.isEmpty() -> Color(0xFF888888)
                            evilTwinAlerts.isEmpty() -> Color(0xFF44BB77)
                            evilTwinAlerts.size == 1 -> Color(0xFFFFAA44)
                            else -> Color(0xFFFF4444)
                        }
                        val etResult = when {
                            wifiDevicesForEt.isEmpty() -> "Scan for WiFi devices first"
                            evilTwinAlerts.isEmpty() -> "No duplicate SSIDs detected"
                            evilTwinAlerts.size == 1 -> "1 suspicious SSID found — possible rogue AP"
                            else -> "${evilTwinAlerts.size} suspicious SSIDs found — possible rogue AP"
                        }
                        Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                            .clickable(enabled = evilTwinAlerts.isNotEmpty()) { evilTwinExpanded = !evilTwinExpanded },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(etIcon, null, tint = etColor, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Evil Twin Detection", fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                                Text(etResult, fontSize = 11.sp, color = subtextColor)
                            }
                            if (evilTwinAlerts.isNotEmpty()) {
                                Icon(
                                    if (evilTwinExpanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                                    null, tint = subtextColor, modifier = Modifier.size(16.dp)
                                )
                            }
                        }
                        AnimatedVisibility(visible = evilTwinExpanded && evilTwinAlerts.isNotEmpty()) {
                            Column(modifier = Modifier.padding(start = 26.dp, top = 4.dp)) {
                                evilTwinAlerts.forEach { alert ->
                                    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                                        Text("SSID: ${alert.ssid}", fontSize = 12.sp, color = textColor, fontWeight = FontWeight.Medium)
                                        Text(alert.reason, fontSize = 11.sp, color = subtextColor)
                                        Text("MAC 1: ${alert.device1Mac}  Signal: ${alert.signalStrength} dBm", fontSize = 11.sp, color = subtextColor)
                                        alert.device2Mac?.let {
                                            Text("MAC 2: $it", fontSize = 11.sp, color = subtextColor)
                                        }
                                    }
                                    Divider(color = subtextColor.copy(alpha = 0.1f))
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text("Avoid connecting. Verify with network owner.", fontSize = 11.sp,
                                    color = Color(0xFFFFAA44), fontWeight = FontWeight.Medium)
                            }
                        }
                    }
                }
            }
        }
    }
}
