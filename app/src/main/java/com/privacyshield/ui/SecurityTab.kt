package com.privacyshield.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.privacyshield.PythonBridge
import com.privacyshield.RootFeatureGate
import com.privacyshield.ArpSpoofResult
import com.privacyshield.ArpScanResult
import com.privacyshield.DeepScanResult
import com.privacyshield.EvilTwinProbeResult
import com.privacyshield.TrafficSummaryResult
import com.privacyshield.model.AppTheme
import com.privacyshield.model.SecurityFeatureInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun SecurityTab(
    currentTheme: AppTheme,
    selectedSecurityFeature: String?,
    onSelectedSecurityFeatureChange: (String?) -> Unit
) {
    val bgColor = MaterialTheme.colorScheme.background
    val cardColor = MaterialTheme.colorScheme.surface
    val textColor = MaterialTheme.colorScheme.onSurface
    val subtextColor = MaterialTheme.colorScheme.onSurfaceVariant

    when (selectedSecurityFeature) {
        "nmap_deep" -> NmapDeepScanScreen(currentTheme, onBack = { onSelectedSecurityFeatureChange(null) })
        "scapy_analyzer" -> ScapyAnalyzerScreen(currentTheme, onBack = { onSelectedSecurityFeatureChange(null) })
        "arp_detection" -> ArpDetectionScreen(currentTheme, onBack = { onSelectedSecurityFeatureChange(null) })
        "traffic_monitor" -> TrafficMonitorScreen(currentTheme, onBack = { onSelectedSecurityFeatureChange(null) })
        "python_script" -> PythonScriptScreen(currentTheme, onBack = { onSelectedSecurityFeatureChange(null) })
        else -> {
            var showWpaSheet by remember { mutableStateOf(false) }
            var showActiveEvilTwinSheet by remember { mutableStateOf(false) }
            var lockedFeatureId by remember { mutableStateOf<String?>(null) }
            val rootAvailable = RootFeatureGate.canUseRootFeatures()
            val securityFeatures = listOf(
                SecurityFeatureInfo("nmap_deep", "Nmap Deep Scan",
                    "OS detection, service versions, vulnerability scripts",
                    Icons.Filled.DocumentScanner,
                    "Performs advanced nmap scans with OS fingerprinting, service version detection and vulnerability scripts. Requires root for raw packet transmission and SYN scanning."),
                SecurityFeatureInfo("scapy_analyzer", "Scapy Analyzer",
                    "Packet inspection and network protocol analysis",
                    Icons.Filled.Analytics,
                    "Uses Scapy to send ARP requests and analyze raw network packets. Requires root to access raw sockets and perform layer-2 network operations."),
                SecurityFeatureInfo("wpa_capture", "WPA Handshake Capture",
                    "Capture WPA/WPA2 handshakes for authorized testing",
                    Icons.Filled.WifiPassword,
                    "Captures WPA/WPA2 4-way handshakes by monitoring 802.11 management frames. Requires monitor mode and root access. Only use on networks you own or have written authorization to test."),
                SecurityFeatureInfo("arp_detection", "ARP Poisoning Detection",
                    "Detect ARP spoofing and MITM attacks on your network",
                    Icons.Filled.Warning,
                    "Monitors ARP traffic in real time to detect IP-to-MAC inconsistencies that may indicate ARP poisoning or man-in-the-middle attacks on your network."),
                SecurityFeatureInfo("active_evil_twin", "Active Evil Twin Detection",
                    "Active probe to identify rogue access points",
                    Icons.Filled.Router,
                    "Sends directed probe requests and listens for multiple BSSIDs responding to the same SSID — a reliable indicator of evil twin access points on your network."),
                SecurityFeatureInfo("traffic_monitor", "Network Traffic Monitor",
                    "Monitor live network traffic and connection stats",
                    Icons.Filled.Timeline,
                    "Captures live network packets and shows real-time statistics including source/destination IPs, protocol breakdown (TCP/UDP/ICMP) and recent connections."),
                SecurityFeatureInfo("python_script", "Python Script Runner",
                    "Run custom Python/Scapy scripts for advanced analysis",
                    Icons.Filled.Code,
                    "Execute custom Python scripts in a sandboxed environment with access to Scapy, socket and JSON libraries for bespoke network analysis and automation.")
            )

            LazyColumn(
                modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding(),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    Column(modifier = Modifier.padding(bottom = 4.dp)) {
                        Text("Advanced Security", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = textColor)
                        Text("Professional network security tools", fontSize = 13.sp, color = subtextColor)
                        Spacer(modifier = Modifier.height(4.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Lock, null, tint = Color(0xFFFFAA44), modifier = Modifier.size(12.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Root access unlocks all features", fontSize = 11.sp, color = Color(0xFFFFAA44))
                        }
                    }
                }
                item {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("ADVANCED SECURITY", fontSize = 11.sp, color = subtextColor, letterSpacing = 1.5.sp,
                        modifier = Modifier.padding(start = 4.dp, bottom = 2.dp))
                    Text("Root access required for full functionality", fontSize = 11.sp,
                        color = subtextColor.copy(alpha = 0.6f),
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp))
                }
                items(securityFeatures) { feature ->
                    Card(
                        modifier = Modifier.fillMaxWidth().clickable {
                            if (rootAvailable) {
                                when (feature.id) {
                                    "nmap_deep" -> onSelectedSecurityFeatureChange("nmap_deep")
                                    "scapy_analyzer" -> onSelectedSecurityFeatureChange("scapy_analyzer")
                                    "wpa_capture" -> showWpaSheet = true
                                    "arp_detection" -> onSelectedSecurityFeatureChange("arp_detection")
                                    "active_evil_twin" -> showActiveEvilTwinSheet = true
                                    "traffic_monitor" -> onSelectedSecurityFeatureChange("traffic_monitor")
                                    "python_script" -> onSelectedSecurityFeatureChange("python_script")
                                }
                            } else {
                                lockedFeatureId = feature.id
                            }
                        },
                        colors = CardDefaults.cardColors(containerColor = cardColor),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(2.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(feature.icon, null, tint = Color(0xFF4A9EFF), modifier = Modifier.size(32.dp))
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(feature.name, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = textColor)
                                Text(feature.description, fontSize = 11.sp, color = subtextColor)
                            }
                            Spacer(modifier = Modifier.width(8.dp))
                            if (rootAvailable) {
                                Surface(color = Color(0xFF1A3A2A), shape = RoundedCornerShape(4.dp)) {
                                    Text("Available", fontSize = 11.sp, color = Color(0xFF44FF88), fontWeight = FontWeight.Medium,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp))
                                }
                            } else {
                                Surface(shape = RoundedCornerShape(4.dp), color = Color.Transparent,
                                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFB71C1C))
                                ) {
                                    Text("Root Required",
                                        color = if (currentTheme == AppTheme.DARK) Color(0xFFEF9A9A) else Color(0xFFB71C1C),
                                        fontSize = 11.sp,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp))
                                }
                            }
                        }
                    }
                }
            }

            val lockedFeature = securityFeatures.find { it.id == lockedFeatureId }
            if (lockedFeature != null) {
                FeatureLockedSheet(feature = lockedFeature, currentTheme = currentTheme, onDismiss = { lockedFeatureId = null })
            }
            if (showWpaSheet) {
                WpaHandshakeSheet(currentTheme = currentTheme, onDismiss = { showWpaSheet = false })
            }
            if (showActiveEvilTwinSheet) {
                ActiveEvilTwinSheet(currentTheme = currentTheme, onDismiss = { showActiveEvilTwinSheet = false })
            }
        }
    }
}

// TASK 5: FeatureLockedSheet — updated text and tappable green box
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FeatureLockedSheet(feature: SecurityFeatureInfo, currentTheme: AppTheme, onDismiss: () -> Unit) {
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val uriHandler = LocalUriHandler.current
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier.padding(24.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(feature.icon, null, tint = Color(0xFF4A9EFF), modifier = Modifier.size(48.dp))
            Spacer(modifier = Modifier.height(12.dp))
            Text(feature.name, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = textColor,
                textAlign = TextAlign.Center)
            Spacer(modifier = Modifier.height(8.dp))
            Text(feature.fullDescription, fontSize = 13.sp, color = subtextColor, textAlign = TextAlign.Center)
            Spacer(modifier = Modifier.height(16.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A2A) else Color(0xFFEEEEFF)),
                shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()
            ) {
                Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                    Icon(Icons.Filled.Lock, null, tint = Color(0xFFFF4444), modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text("Why root?", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = textColor)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("This feature requires raw socket access or system-level network permissions only available to root users.",
                            fontSize = 12.sp, color = subtextColor)
                    }
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            // TASK 5: tappable green box opening GitHub URL
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = Color(0xFF2E7D32),
                modifier = Modifier.fillMaxWidth().clickable {
                    uriHandler.openUri("https://github.com/blank-0x/privacy-shield")
                }
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Get Dev Build", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("The dev build unlocks all root features. Contact us on GitHub for access.",
                        fontSize = 14.sp, color = Color.White.copy(alpha = 0.9f))
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
            OutlinedButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                Text("Dismiss")
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WpaHandshakeSheet(currentTheme: AppTheme, onDismiss: () -> Unit) {
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    var authorized by remember { mutableStateOf(false) }
    var interfaceName by remember { mutableStateOf("wlan0") }
    var bssid by remember { mutableStateOf("") }
    var channel by remember { mutableStateOf("6") }
    var status by remember { mutableStateOf("") }
    var loading by remember { mutableStateOf(false) }
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(modifier = Modifier.padding(24.dp).fillMaxWidth()) {
            Text("WPA Handshake Capture", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = textColor)
            Spacer(modifier = Modifier.height(16.dp))
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF3A1A1A)), shape = RoundedCornerShape(8.dp)) {
                Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                    Icon(Icons.Filled.Warning, null, tint = Color(0xFFFFAA44), modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Authorized testing only. Capturing handshakes on networks you don't own is illegal.",
                        fontSize = 12.sp, color = Color(0xFFFFAA44))
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.clickable { authorized = !authorized }.fillMaxWidth()) {
                Checkbox(checked = authorized, onCheckedChange = { authorized = it })
                Spacer(modifier = Modifier.width(8.dp))
                Text("I confirm I have authorization to test this network", fontSize = 13.sp, color = textColor)
            }
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedTextField(value = interfaceName, onValueChange = { interfaceName = it },
                label = { Text("Interface") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(value = bssid, onValueChange = { bssid = it },
                label = { Text("BSSID (target AP MAC)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(value = channel, onValueChange = { channel = it },
                label = { Text("Channel") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(modifier = Modifier.height(12.dp))
            Card(colors = CardDefaults.cardColors(containerColor = if (currentTheme == AppTheme.DARK) Color(0xFF0A0A2A) else Color(0xFFE8EAF6)),
                shape = RoundedCornerShape(8.dp)) {
                Text("This feature requires monitor mode.\nUse: airmon-ng start $interfaceName",
                    fontSize = 12.sp, color = Color(0xFF4A9EFF), modifier = Modifier.padding(12.dp))
            }
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    status = "Checking monitor mode..."
                    loading = true
                    scope.launch(Dispatchers.IO) {
                        val result = PythonBridge.checkMonitorMode(context, interfaceName)
                        withContext(Dispatchers.Main) {
                            loading = false
                            status = if (result.isMonitor) "Interface is in monitor mode. Starting capture on channel $channel..."
                                     else "Monitor mode not detected. Run: airmon-ng start $interfaceName"
                        }
                    }
                },
                enabled = authorized && !loading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (loading) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.Black)
                else Icon(Icons.Filled.WifiPassword, null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (loading) "Checking..." else "Start Capture")
            }
            if (status.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(status, fontSize = 13.sp, color = subtextColor)
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActiveEvilTwinSheet(currentTheme: AppTheme, onDismiss: () -> Unit) {
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val context = androidx.compose.ui.platform.LocalContext.current
    val currentSsid = remember {
        try {
            @Suppress("DEPRECATION")
            val wm = context.getSystemService(android.content.Context.WIFI_SERVICE) as android.net.wifi.WifiManager
            wm.connectionInfo.ssid?.removeSurrounding("\"") ?: ""
        } catch (e: Exception) { "" }
    }
    var targetSsid by remember { mutableStateOf(currentSsid) }
    var loading by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<EvilTwinProbeResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(modifier = Modifier.padding(24.dp).fillMaxWidth()) {
            Text("Active Evil Twin Detection", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = textColor)
            Spacer(modifier = Modifier.height(8.dp))
            Text("Actively probes nearby networks to detect rogue APs impersonating legitimate ones",
                fontSize = 13.sp, color = subtextColor)
            Spacer(modifier = Modifier.height(16.dp))
            OutlinedTextField(value = targetSsid, onValueChange = { targetSsid = it },
                label = { Text("Target SSID") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    loading = true; error = null; result = null
                    scope.launch(Dispatchers.IO) {
                        val r = PythonBridge.probeForEvilTwin(context, targetSsid)
                        withContext(Dispatchers.Main) { loading = false; result = r; if (!r.success) error = r.error }
                    }
                },
                enabled = !loading && targetSsid.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (loading) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.Black)
                else Icon(Icons.Filled.Router, null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (loading) "Scanning..." else "Start Active Scan")
            }
            error?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text("Error: $it", color = Color(0xFFFF6666), fontSize = 12.sp)
            }
            result?.let { r ->
                Spacer(modifier = Modifier.height(12.dp))
                if (r.evilTwinSuspected) {
                    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF3A1A1A)), shape = RoundedCornerShape(8.dp)) {
                        Row(modifier = Modifier.padding(12.dp)) {
                            Icon(Icons.Filled.Warning, null, tint = Color(0xFFFF4444), modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Evil twin suspected! Multiple BSSIDs for '${r.ssid}'", color = Color(0xFFFF4444), fontSize = 13.sp)
                        }
                    }
                } else {
                    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF1A3A2A)), shape = RoundedCornerShape(8.dp)) {
                        Row(modifier = Modifier.padding(12.dp)) {
                            Icon(Icons.Filled.CheckCircle, null, tint = Color(0xFF44BB77), modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("No evil twin detected for '${r.ssid}'", color = Color(0xFF44BB77), fontSize = 13.sp)
                        }
                    }
                }
                if (r.responses.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    r.responses.forEach { resp ->
                        Text("BSSID: ${resp.bssid} • Signal: ${resp.signal} dBm", fontSize = 12.sp, color = textColor)
                    }
                }
            }
            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
fun NmapDeepScanScreen(currentTheme: AppTheme, onBack: () -> Unit) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val context = androidx.compose.ui.platform.LocalContext.current
    val gatewayIp = remember {
        try {
            val wm = context.getSystemService(android.content.Context.WIFI_SERVICE) as android.net.wifi.WifiManager
            val dhcp = wm.dhcpInfo
            "%d.%d.%d.%d".format(dhcp.gateway and 0xff, dhcp.gateway shr 8 and 0xff,
                dhcp.gateway shr 16 and 0xff, dhcp.gateway shr 24 and 0xff)
        } catch (e: Exception) { "" }
    }
    var target by remember { mutableStateOf(gatewayIp) }
    var selectedProfile by remember { mutableStateOf(0) }
    var loading by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<DeepScanResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val profiles = listOf(
        "Quick" to "-sV -T4 --top-ports 100",
        "Full" to "-sV -sC -T4 --top-ports 1000",
        "OS Detect" to "-sV -O -T4",
        "Vuln Scan" to "-sV --script vuln -T4"
    )
    Column(modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = textColor)
            }
            Text("Nmap Deep Scan", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = textColor)
        }
        LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                OutlinedTextField(value = target, onValueChange = { target = it },
                    label = { Text("Target IP / Range") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
            }
            item {
                Text("Scan Profile", fontSize = 12.sp, color = subtextColor)
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    profiles.forEachIndexed { i, (label, _) ->
                        FilterChip(selected = selectedProfile == i, onClick = { selectedProfile = i },
                            label = { Text(label, fontSize = 12.sp) })
                    }
                }
            }
            item {
                Button(
                    onClick = {
                        loading = true; error = null; result = null
                        scope.launch(Dispatchers.IO) {
                            val r = PythonBridge.runDeepScan(context, target, profiles[selectedProfile].second)
                            withContext(Dispatchers.Main) { loading = false; result = r; if (!r.success) error = r.error }
                        }
                    },
                    enabled = !loading && target.isNotBlank(),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (loading) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.Black)
                    else Icon(Icons.Filled.DocumentScanner, null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(if (loading) "Scanning..." else "Start Deep Scan")
                }
            }
            error?.let {
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF3A1A1A)), shape = RoundedCornerShape(8.dp)) {
                        Text(it, color = Color(0xFFFF6666), modifier = Modifier.padding(12.dp), fontSize = 13.sp)
                    }
                }
            }
            result?.takeIf { it.success }?.let { r ->
                if (r.hosts.isEmpty()) {
                    item { Text("No hosts found", color = subtextColor, modifier = Modifier.padding(8.dp)) }
                }
                items(r.hosts) { host ->
                    Card(colors = CardDefaults.cardColors(containerColor = cardColor), shape = RoundedCornerShape(12.dp)) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(host.ip, fontWeight = FontWeight.Bold, color = textColor, fontSize = 16.sp)
                                Spacer(modifier = Modifier.width(8.dp))
                                if (host.hostname.isNotEmpty()) Text("(${host.hostname})", color = subtextColor, fontSize = 12.sp)
                            }
                            if (host.os.isNotEmpty()) {
                                Text("OS: ${host.os.first().name} — ${host.os.first().accuracy}% match",
                                    color = Color(0xFF4A9EFF), fontSize = 12.sp)
                            }
                            val openPorts = host.ports.filter { it.state == "open" }
                            if (openPorts.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                openPorts.forEach { port ->
                                    Row(modifier = Modifier.padding(vertical = 2.dp)) {
                                        Text("${port.port}/${port.protocol}", color = Color(0xFF44FF88), fontSize = 12.sp,
                                            modifier = Modifier.width(90.dp))
                                        Text("${port.service} ${port.version}".trim().ifEmpty { port.product },
                                            color = textColor, fontSize = 12.sp, modifier = Modifier.weight(1f))
                                    }
                                }
                            }
                        }
                    }
                }
                item {
                    OutlinedButton(
                        onClick = {
                            val text = r.hosts.joinToString("\n\n") { h ->
                                "${h.ip}${if (h.hostname.isNotEmpty()) " (${h.hostname})" else ""}\n" +
                                h.os.firstOrNull()?.let { "OS: ${it.name}\n" }.orEmpty() +
                                h.ports.filter { it.state == "open" }.joinToString("\n") { "${it.port}: ${it.service} ${it.version}" }
                            }
                            val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                type = "text/plain"; putExtra(android.content.Intent.EXTRA_TEXT, text)
                            }
                            context.startActivity(android.content.Intent.createChooser(intent, "Share Results"))
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Filled.Share, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Share Results")
                    }
                }
            }
        }
    }
}

@Composable
fun ScapyAnalyzerScreen(currentTheme: AppTheme, onBack: () -> Unit) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val context = androidx.compose.ui.platform.LocalContext.current
    val gatewayNetwork = remember {
        try {
            val wm = context.getSystemService(android.content.Context.WIFI_SERVICE) as android.net.wifi.WifiManager
            val dhcp = wm.dhcpInfo
            val gw = dhcp.gateway
            "${gw and 0xff}.${gw shr 8 and 0xff}.${gw shr 16 and 0xff}.0/24"
        } catch (e: Exception) { "192.168.1.0/24" }
    }
    var arpNetwork by remember { mutableStateOf(gatewayNetwork) }
    var interfaceInfo by remember { mutableStateOf("") }
    var interfaceLoading by remember { mutableStateOf(false) }
    var arpLoading by remember { mutableStateOf(false) }
    var arpResult by remember { mutableStateOf<ArpScanResult?>(null) }
    var arpError by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    Column(modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = textColor)
            }
            Text("Scapy Analyzer", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = textColor)
        }
        LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                Card(colors = CardDefaults.cardColors(containerColor = cardColor), shape = RoundedCornerShape(12.dp)) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("INTERFACE INFO", fontSize = 11.sp, color = subtextColor, letterSpacing = 1.5.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        if (interfaceInfo.isNotEmpty()) {
                            Text(interfaceInfo, fontSize = 12.sp, color = textColor, fontFamily = FontFamily.Monospace)
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                        Button(
                            onClick = {
                                interfaceLoading = true
                                scope.launch(Dispatchers.IO) {
                                    val info = PythonBridge.getInterfaceInfo(context)
                                    withContext(Dispatchers.Main) {
                                        interfaceLoading = false
                                        interfaceInfo = try {
                                            val obj = org.json.JSONObject(info)
                                            val arr = obj.optJSONArray("interfaces")
                                            if (arr != null) {
                                                (0 until arr.length()).joinToString("\n") { i ->
                                                    val iface = arr.getJSONObject(i)
                                                    "${iface.getString("interface")}: ${iface.getString("address")}"
                                                }
                                            } else info
                                        } catch (e: Exception) { info }
                                    }
                                }
                            },
                            enabled = !interfaceLoading,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            if (interfaceLoading) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.Black)
                            else Icon(Icons.Filled.NetworkCheck, null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(if (interfaceLoading) "Loading..." else "Get Interface Info")
                        }
                    }
                }
            }
            item {
                Card(colors = CardDefaults.cardColors(containerColor = cardColor), shape = RoundedCornerShape(12.dp)) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("ARP SCAN", fontSize = 11.sp, color = subtextColor, letterSpacing = 1.5.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(value = arpNetwork, onValueChange = { arpNetwork = it },
                            label = { Text("Network (CIDR)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = {
                                arpLoading = true; arpError = null; arpResult = null
                                scope.launch(Dispatchers.IO) {
                                    val r = PythonBridge.runArpScan(context, arpNetwork)
                                    withContext(Dispatchers.Main) { arpLoading = false; arpResult = r; if (!r.success) arpError = r.error }
                                }
                            },
                            enabled = !arpLoading && arpNetwork.isNotBlank(),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            if (arpLoading) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.Black)
                            else Icon(Icons.Filled.Radar, null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(if (arpLoading) "Scanning..." else "ARP Scan")
                        }
                    }
                }
            }
            arpError?.let {
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF3A1A1A)), shape = RoundedCornerShape(8.dp)) {
                        Text(it, color = Color(0xFFFF6666), modifier = Modifier.padding(12.dp), fontSize = 13.sp)
                    }
                }
            }
            arpResult?.takeIf { it.success }?.let { r ->
                if (r.hosts.isEmpty()) {
                    item { Text("No hosts found", color = subtextColor) }
                } else {
                    item {
                        Card(colors = CardDefaults.cardColors(containerColor = cardColor), shape = RoundedCornerShape(12.dp)) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("${r.hosts.size} HOST(S) FOUND", fontSize = 11.sp, color = subtextColor, letterSpacing = 1.5.sp)
                                Spacer(modifier = Modifier.height(8.dp))
                                r.hosts.forEach { host ->
                                    Row(modifier = Modifier.padding(vertical = 4.dp)) {
                                        Text(host.ip, color = Color(0xFF44FF88), fontSize = 13.sp, modifier = Modifier.width(140.dp))
                                        Text(host.mac, color = subtextColor, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ArpDetectionScreen(currentTheme: AppTheme, onBack: () -> Unit) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val context = androidx.compose.ui.platform.LocalContext.current
    var interfaceName by remember { mutableStateOf("wlan0") }
    var monitoring by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<ArpSpoofResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(monitoring) {
        if (monitoring) {
            while (monitoring) {
                val r = withContext(Dispatchers.IO) { PythonBridge.detectArpSpoofing(context, interfaceName, 5) }
                result = r
                if (!r.success) { error = r.error; monitoring = false; break }
                delay(2000)
            }
        }
    }
    Column(modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { onBack(); monitoring = false }) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = textColor)
            }
            Text("ARP Poisoning Detection", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = textColor)
        }
        LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                OutlinedTextField(value = interfaceName, onValueChange = { interfaceName = it },
                    label = { Text("Interface") }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                    enabled = !monitoring)
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = { monitoring = !monitoring; error = null },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = if (monitoring) Color(0xFFFF4444) else Color(0xFF44BB77))
                ) {
                    Icon(if (monitoring) Icons.Filled.Stop else Icons.Filled.PlayArrow, null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(if (monitoring) "Stop Monitoring" else "Start Monitoring")
                }
            }
            if (monitoring) {
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color(0xFF44BB77))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Monitoring ARP traffic on $interfaceName...", fontSize = 13.sp, color = subtextColor)
                    }
                }
            }
            error?.let {
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF3A1A1A)), shape = RoundedCornerShape(8.dp)) {
                        Text(it, color = Color(0xFFFF6666), modifier = Modifier.padding(12.dp), fontSize = 13.sp)
                    }
                }
            }
            result?.takeIf { it.success }?.let { r ->
                if (r.anomalies.isEmpty()) {
                    item {
                        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF1A3A2A)), shape = RoundedCornerShape(12.dp)) {
                            Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.CheckCircle, null, tint = Color(0xFF44BB77), modifier = Modifier.size(20.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text("No ARP anomalies detected", fontSize = 14.sp, color = Color(0xFF44BB77), fontWeight = FontWeight.Medium)
                                    Text("${r.hostsSeen} host(s) observed", fontSize = 12.sp, color = Color(0xFF44BB77).copy(alpha = 0.7f))
                                }
                            }
                        }
                    }
                } else {
                    item { Text("${r.anomalies.size} ANOMALY(S) DETECTED", fontSize = 11.sp, color = Color(0xFFFF4444), letterSpacing = 1.5.sp) }
                    items(r.anomalies) { anomaly ->
                        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF3A1A1A)), shape = RoundedCornerShape(12.dp)) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Row {
                                    Icon(Icons.Filled.Warning, null, tint = Color(0xFFFF4444), modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("ARP Spoof — ${anomaly.ip}", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFFFF4444))
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                Text("Old MAC: ${anomaly.oldMac}", fontSize = 12.sp, color = textColor, fontFamily = FontFamily.Monospace)
                                Text("New MAC: ${anomaly.newMac}", fontSize = 12.sp, color = Color(0xFFFF4444), fontFamily = FontFamily.Monospace)
                                Text("At: ${anomaly.timestamp}", fontSize = 11.sp, color = subtextColor)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun TrafficMonitorScreen(currentTheme: AppTheme, onBack: () -> Unit) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val context = androidx.compose.ui.platform.LocalContext.current
    var interfaceName by remember { mutableStateOf("wlan0") }
    var monitoring by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<TrafficSummaryResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(monitoring) {
        if (monitoring) {
            while (monitoring) {
                val r = withContext(Dispatchers.IO) { PythonBridge.captureTrafficSummary(context, interfaceName, 2) }
                if (r.success) result = r else { error = r.error; monitoring = false; break }
                delay(500)
            }
        }
    }
    Column(modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { onBack(); monitoring = false }) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = textColor)
            }
            Text("Network Traffic Monitor", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = textColor)
        }
        LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(value = interfaceName, onValueChange = { interfaceName = it },
                        label = { Text("Interface") }, modifier = Modifier.weight(1f), singleLine = true,
                        enabled = !monitoring)
                    Button(
                        onClick = { monitoring = !monitoring; error = null },
                        colors = ButtonDefaults.buttonColors(containerColor = if (monitoring) Color(0xFFFF4444) else Color(0xFF44BB77))
                    ) {
                        Icon(if (monitoring) Icons.Filled.Stop else Icons.Filled.PlayArrow, null)
                    }
                }
            }
            result?.takeIf { it.success }?.let { r ->
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = cardColor), shape = RoundedCornerShape(12.dp)) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text("LIVE STATS", fontSize = 11.sp, color = subtextColor, letterSpacing = 1.5.sp)
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text("${r.packetCount}", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = Color(0xFF4A9EFF))
                                    Text("Packets", fontSize = 10.sp, color = subtextColor)
                                }
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text("${r.uniqueIps}", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = Color(0xFF44BB77))
                                    Text("Unique IPs", fontSize = 10.sp, color = subtextColor)
                                }
                            }
                            Spacer(modifier = Modifier.height(12.dp))
                            Text("PROTOCOLS", fontSize = 10.sp, color = subtextColor, letterSpacing = 1.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            val total = r.protocols.values.sum().coerceAtLeast(1)
                            val protoColors = mapOf("TCP" to Color(0xFF4A9EFF), "UDP" to Color(0xFF44FF88), "ICMP" to Color(0xFFFFAA44), "Other" to Color(0xFF666666))
                            r.protocols.forEach { (proto, count) ->
                                Row(modifier = Modifier.padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                                    Text(proto, fontSize = 12.sp, color = protoColors[proto] ?: textColor, modifier = Modifier.width(50.dp))
                                    Box(modifier = Modifier.weight(1f).height(8.dp).clip(RoundedCornerShape(4.dp)).background(subtextColor.copy(alpha = 0.2f))) {
                                        Box(modifier = Modifier.fillMaxHeight().fillMaxWidth(count.toFloat() / total).background(protoColors[proto] ?: textColor))
                                    }
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("$count", fontSize = 11.sp, color = subtextColor)
                                }
                            }
                        }
                    }
                }
                if (r.recentPackets.isNotEmpty()) {
                    item { Text("RECENT PACKETS", fontSize = 11.sp, color = subtextColor, letterSpacing = 1.5.sp) }
                    items(r.recentPackets) { pkt ->
                        Card(colors = CardDefaults.cardColors(containerColor = cardColor), shape = RoundedCornerShape(8.dp)) {
                            Row(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                                Text(pkt.src, fontSize = 11.sp, color = Color(0xFF4A9EFF), modifier = Modifier.weight(1f))
                                Icon(Icons.Filled.KeyboardArrowRight, null, tint = subtextColor, modifier = Modifier.size(14.dp))
                                Text(pkt.dst, fontSize = 11.sp, color = textColor, modifier = Modifier.weight(1f),
                                    textAlign = TextAlign.End)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(pkt.protocol, fontSize = 10.sp, color = subtextColor)
                            }
                        }
                    }
                }
            }
            error?.let {
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF3A1A1A)), shape = RoundedCornerShape(8.dp)) {
                        Text(it, color = Color(0xFFFF6666), modifier = Modifier.padding(12.dp), fontSize = 13.sp)
                    }
                }
            }
        }
    }
}

@Composable
fun PythonScriptScreen(currentTheme: AppTheme, onBack: () -> Unit) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val consoleBg = Color(0xFF0D0D0D)
    val context = androidx.compose.ui.platform.LocalContext.current
    val exampleScripts = listOf(
        "ARP Scan" to """import socket\nfor i in range(1, 20):\n    try:\n        host = "192.168.1." + str(i)\n        s = socket.create_connection((host, 80), timeout=0.3)\n        print(f"{host}: port 80 open")\n        s.close()\n    except: pass""",
        "DNS Lookup" to """import socket\nhosts = ["google.com","github.com","cloudflare.com"]\nfor h in hosts:\n    try:\n        ip = socket.gethostbyname(h)\n        print(f"{h} -> {ip}")\n    except Exception as e:\n        print(f"{h}: {e}")""",
        "Port Probe" to """import socket\ntarget = "8.8.8.8"\nfor port in [53, 80, 443]:\n    try:\n        s = socket.create_connection((target, port), timeout=1)\n        print(f"Port {port}: OPEN")\n        s.close()\n    except:\n        print(f"Port {port}: closed")""",
        "Ping Sweep" to """import socket\nsubnet = "192.168.1"\nprint("Scanning", subnet + ".1-20...")\nfor i in range(1, 21):\n    host = f"{subnet}.{i}"\n    try:\n        socket.create_connection((host, 80), 0.3).close()\n        print(f"{host}: UP")\n    except: pass"""
    )
    var script by remember { mutableStateOf(exampleScripts[0].second.replace("\\n", "\n")) }
    var output by remember { mutableStateOf("") }
    var running by remember { mutableStateOf(false) }
    var showDropdown by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    Column(modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()) {
        Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = textColor)
            }
            Text("Python Script Runner", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = textColor, modifier = Modifier.weight(1f))
            Box {
                IconButton(onClick = { showDropdown = true }) {
                    Icon(Icons.Filled.MoreVert, null, tint = textColor)
                }
                DropdownMenu(expanded = showDropdown, onDismissRequest = { showDropdown = false }) {
                    exampleScripts.forEach { (name, code) ->
                        DropdownMenuItem(
                            text = { Text(name) },
                            onClick = { script = code.replace("\\n", "\n"); showDropdown = false }
                        )
                    }
                }
            }
        }
        LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                Card(colors = CardDefaults.cardColors(containerColor = consoleBg), shape = RoundedCornerShape(8.dp)) {
                    OutlinedTextField(
                        value = script,
                        onValueChange = { script = it },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 160.dp),
                        textStyle = androidx.compose.ui.text.TextStyle(
                            fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = Color(0xFF44FF88)
                        ),
                        colors = OutlinedTextFieldDefaults.colors(
                            unfocusedBorderColor = Color(0xFF2A2A2A), focusedBorderColor = Color(0xFF44FF88)
                        ),
                        placeholder = { Text("# Write Python script here...", color = Color(0xFF444444), fontFamily = FontFamily.Monospace, fontSize = 13.sp) }
                    )
                }
            }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            running = true; output = ""
                            scope.launch(Dispatchers.IO) {
                                val r = PythonBridge.runCustomScript(context, script)
                                withContext(Dispatchers.Main) {
                                    running = false
                                    output = buildString {
                                        if (r.output.isNotEmpty()) append(r.output)
                                        if (r.errors.isNotEmpty()) append("\n[ERROR] ${r.errors}")
                                    }.trim()
                                }
                            }
                        },
                        enabled = !running && script.isNotBlank(),
                        modifier = Modifier.weight(1f)
                    ) {
                        if (running) CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.Black)
                        else Icon(Icons.Filled.PlayArrow, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(if (running) "Running..." else "Run")
                    }
                    OutlinedButton(onClick = { output = "" }, enabled = output.isNotEmpty()) {
                        Icon(Icons.Filled.Clear, null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Clear")
                    }
                    if (output.isNotEmpty()) {
                        OutlinedButton(onClick = {
                            val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                type = "text/plain"; putExtra(android.content.Intent.EXTRA_TEXT, output)
                            }
                            context.startActivity(android.content.Intent.createChooser(intent, "Share Output"))
                        }) {
                            Icon(Icons.Filled.Share, null, modifier = Modifier.size(16.dp))
                        }
                    }
                }
            }
            if (output.isNotEmpty()) {
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = consoleBg), shape = RoundedCornerShape(8.dp)) {
                        Text(output, modifier = Modifier.padding(12.dp).fillMaxWidth(),
                            fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Color(0xFF44FF88))
                    }
                }
            }
        }
    }
}
