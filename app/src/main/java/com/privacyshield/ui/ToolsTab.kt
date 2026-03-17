package com.privacyshield.ui

import android.net.wifi.WifiManager
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.privacyshield.PythonBridge
import com.privacyshield.RootFeatureGate
import com.privacyshield.model.AppTheme
import com.privacyshield.model.CveResult
import com.privacyshield.model.DetectedDevice
import com.privacyshield.model.PortScanResult
import com.privacyshield.model.TraceHop
import com.privacyshield.model.getCveSeverity
import com.privacyshield.model.isValidNetworkTarget
import com.privacyshield.NmapScanResult
import com.privacyshield.ServiceScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ToolsTab(
    currentTheme: AppTheme,
    devices: List<DetectedDevice>,
    wifiManager: WifiManager,
    nmapTarget: String,
    onNmapTargetChange: (String) -> Unit,
    nmapResults: NmapScanResult?,
    nmapLoading: Boolean,
    nmapError: String?,
    serviceTarget: String,
    onServiceTargetChange: (String) -> Unit,
    serviceResults: ServiceScanResult?,
    serviceLoading: Boolean,
    serviceError: String?,
    pythonScanTab: Int,
    onPythonScanTabChange: (Int) -> Unit,
    onLaunchHostScan: () -> Unit,
    onLaunchServiceScan: (String) -> Unit,
    getTimeAgo: (Long) -> String
) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    val serviceNames = remember {
        mapOf(21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS",
            80 to "HTTP", 110 to "POP3", 143 to "IMAP", 443 to "HTTPS", 445 to "SMB",
            3306 to "MySQL", 3389 to "RDP", 5432 to "PostgreSQL", 5984 to "CouchDB",
            6379 to "Redis", 8080 to "HTTP-Alt", 8443 to "HTTPS-Alt", 8883 to "MQTT-SSL",
            1883 to "MQTT", 27017 to "MongoDB", 1433 to "MSSQL", 1521 to "Oracle",
            4840 to "OPC-UA", 5683 to "CoAP", 9200 to "Elasticsearch",
            3000 to "Dev", 4000 to "Dev", 5000 to "Dev", 8000 to "HTTP-Alt", 9000 to "Dev")
    }
    val presetGroups = remember {
        mapOf(
            "Common" to listOf(21,22,23,25,53,80,110,143,443,445,3389,8080,8443),
            "Web" to listOf(80,443,8080,8443,3000,4000,5000,8000,9000),
            "Database" to listOf(1433,1521,3306,5432,5984,6379,27017),
            "IoT" to listOf(1883,4840,5683,8883,9200)
        )
    }

    val defaultIp = remember {
        try {
            val dhcpInfo = wifiManager.dhcpInfo
            if (dhcpInfo != null && dhcpInfo.gateway != 0) {
                "%d.%d.%d.%d".format(dhcpInfo.gateway and 0xff, dhcpInfo.gateway shr 8 and 0xff,
                    dhcpInfo.gateway shr 16 and 0xff, dhcpInfo.gateway shr 24 and 0xff)
            } else ""
        } catch (e: Exception) { "" }
    }

    var targetIp by remember { mutableStateOf(defaultIp) }
    var selectedPreset by remember { mutableStateOf<String?>("Common") }
    var customFromPort by remember { mutableStateOf("") }
    var customToPort by remember { mutableStateOf("") }
    var isPortScanning by remember { mutableStateOf(false) }
    var portScanProgress by remember { mutableStateOf(0f) }
    var portResults by remember { mutableStateOf<List<Triple<Int, Boolean, String>>>(emptyList()) }
    var showAllPorts by remember { mutableStateOf(false) }
    var scanJob by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    var portScanHistory by remember { mutableStateOf<List<PortScanResult>>(emptyList()) }
    var expandedHistoryIndex by remember { mutableStateOf<Int?>(null) }
    var pingTarget by remember { mutableStateOf(defaultIp) }
    var pingResults by remember { mutableStateOf<List<Pair<String, Long?>>>(emptyList()) }
    var isPinging by remember { mutableStateOf(false) }
    var whoisTarget by remember { mutableStateOf("") }
    var whoisResult by remember { mutableStateOf<Map<String, String>?>(null) }
    var whoisError by remember { mutableStateOf("") }
    var isWhoisLoading by remember { mutableStateOf(false) }
    var traceTarget by remember { mutableStateOf(defaultIp) }
    var traceResults by remember { mutableStateOf<List<TraceHop>>(emptyList()) }
    var isTracing by remember { mutableStateOf(false) }
    var traceJob by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    var cveLookupQuery by remember { mutableStateOf("") }
    var cveResults by remember { mutableStateOf<List<CveResult>>(emptyList()) }
    var cveLookupLoading by remember { mutableStateOf(false) }
    var cveLookupError by remember { mutableStateOf<String?>(null) }
    var servicePorts by remember { mutableStateOf("22,80,443,8080,8443") }
    var servicePortPreset by remember { mutableStateOf(0) }

    // TASK 2: Lazy Chaquopy init when ToolsTab becomes visible
    var pythonInitialized by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (!pythonInitialized) {
            withContext(Dispatchers.IO) {
                PythonBridge.init(context)
            }
            pythonInitialized = true
        }
    }

    // Fallback: re-try gateway IP if targetIp is still empty; also derive nmap subnet
    LaunchedEffect(Unit) {
        if (targetIp.isEmpty() || nmapTarget.isEmpty()) {
            try {
                val dhcp = withContext(Dispatchers.IO) { wifiManager.dhcpInfo }
                if (dhcp != null && dhcp.gateway != 0) {
                    val gw = "%d.%d.%d.%d".format(
                        dhcp.gateway and 0xff, dhcp.gateway shr 8 and 0xff,
                        dhcp.gateway shr 16 and 0xff, dhcp.gateway shr 24 and 0xff)
                    if (targetIp.isEmpty()) targetIp = gw
                    if (serviceTarget.isEmpty()) onServiceTargetChange(gw)
                    if (nmapTarget.isEmpty()) {
                        val parts = gw.split(".")
                        if (parts.size == 4) onNmapTargetChange("${parts[0]}.${parts[1]}.${parts[2]}.0/24")
                    }
                }
            } catch (e: Exception) { }
        }
    }

    fun getPorts(): List<Int> {
        if (customFromPort.isNotEmpty() && customToPort.isNotEmpty()) {
            val from = customFromPort.toIntOrNull() ?: 1
            val to = customToPort.toIntOrNull() ?: 1024
            return (from..minOf(to, from + 999)).toList()
        }
        return presetGroups[selectedPreset] ?: presetGroups["Common"]!!
    }

    suspend fun doWhoisLookup(target: String) {
        if (isWhoisLoading || target.isEmpty()) return
        whoisTarget = target
        isWhoisLoading = true
        whoisResult = null
        whoisError = ""
        try {
            val ip = if (target.matches(Regex("\\d+\\.\\d+\\.\\d+\\.\\d+"))) target
                     else withContext(Dispatchers.IO) { InetAddress.getByName(target).hostAddress ?: target }
            val json = withContext(Dispatchers.IO) {
                val url = java.net.URL("https://ipinfo.io/$ip/json")
                val conn = url.openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 5000; conn.readTimeout = 5000
                try { conn.inputStream.bufferedReader().readText() } finally { conn.disconnect() }
            }
            val obj = org.json.JSONObject(json)
            if (obj.has("error")) {
                val errMsg = obj.optJSONObject("error")?.optString("message")
                    ?: obj.optJSONObject("error")?.optString("title")
                    ?: "Lookup failed"
                whoisError = "Lookup failed: $errMsg"
            } else {
                val result = mutableMapOf<String, String>()
                obj.optString("ip").takeIf { it.isNotEmpty() }?.let { result["IP Address"] = it }
                obj.optString("hostname").takeIf { it.isNotEmpty() }?.let { result["Hostname"] = it }
                val city = obj.optString("city", "")
                val region = obj.optString("region", "")
                val country = obj.optString("country", "")
                val location = listOf(city, region, country).filter { it.isNotEmpty() }.joinToString(", ")
                if (location.isNotEmpty()) result["Location"] = location
                obj.optString("org").takeIf { it.isNotEmpty() }?.let { result["ISP / Org"] = it }
                val loc = obj.optString("loc", "")
                if (loc.isNotEmpty()) {
                    val parts = loc.split(",")
                    if (parts.size == 2) result["Coordinates"] = "Lat: ${parts[0]}, Lon: ${parts[1]}"
                }
                obj.optString("timezone").takeIf { it.isNotEmpty() }?.let { result["Timezone"] = it }
                if (result.isEmpty()) whoisError = "No data returned"
                else whoisResult = result
            }
        } catch (e: Exception) { whoisError = "Error: ${e.message ?: "Unknown error"}" }
        isWhoisLoading = false
    }

    suspend fun doCveLookup(query: String) {
        if (cveLookupLoading || query.isEmpty()) return
        cveLookupLoading = true
        cveResults = emptyList()
        cveLookupError = null
        try {
            val parts = query.trim().split(Regex("[\\s/,]+")).filter { it.isNotEmpty() }
            val vendor = parts.getOrNull(0)?.lowercase() ?: run {
                cveLookupLoading = false; return
            }
            val product = parts.getOrNull(1)?.lowercase()

            fun fetchUrl(urlStr: String): String {
                val url = java.net.URL(urlStr)
                val conn = url.openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 8000; conn.readTimeout = 8000
                return try { conn.inputStream.bufferedReader().readText() } finally { conn.disconnect() }
            }

            val encodedVendor = java.net.URLEncoder.encode(vendor, "UTF-8")
            val encodedProduct = product?.let { java.net.URLEncoder.encode(it, "UTF-8") }

            val circlResults: List<CveResult> = try {
                val circlJson = withContext(Dispatchers.IO) {
                    val primaryUrl = if (encodedProduct != null)
                        "https://cve.circl.lu/api/search/$encodedVendor/$encodedProduct"
                    else "https://cve.circl.lu/api/search/$encodedVendor"
                    try { fetchUrl(primaryUrl) } catch (e: Exception) {
                        if (encodedProduct != null) fetchUrl("https://cve.circl.lu/api/search/$encodedVendor")
                        else throw e
                    }
                }
                val arr = org.json.JSONArray(circlJson)
                (0 until minOf(arr.length(), 20)).map { i ->
                    val obj = arr.getJSONObject(i)
                    CveResult(
                        id = obj.optString("id", "Unknown"),
                        summary = obj.optString("summary", "No description available"),
                        cvss = obj.optDouble("cvss", Double.NaN).takeIf { !it.isNaN() },
                        published = obj.optString("Published", ""),
                        references = obj.optJSONArray("references")?.let { refs ->
                            (0 until refs.length()).map { refs.getString(it) }
                        } ?: emptyList(),
                        source = "CIRCL"
                    )
                }
            } catch (e: Exception) { emptyList() }

            if (circlResults.isNotEmpty()) {
                cveResults = circlResults
            } else {
                val nvdResults: List<CveResult> = try {
                    val encoded = java.net.URLEncoder.encode(query.trim(), "UTF-8")
                    val nvdJson = withContext(Dispatchers.IO) {
                        fetchUrl("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$encoded&resultsPerPage=20")
                    }
                    val root = org.json.JSONObject(nvdJson)
                    val vulns = root.optJSONArray("vulnerabilities") ?: org.json.JSONArray()
                    (0 until minOf(vulns.length(), 20)).mapNotNull { i ->
                        val cveObj = vulns.getJSONObject(i).optJSONObject("cve") ?: return@mapNotNull null
                        val id = cveObj.optString("id", "Unknown")
                        val descs = cveObj.optJSONArray("descriptions")
                        val summary = (0 until (descs?.length() ?: 0))
                            .map { descs!!.getJSONObject(it) }
                            .firstOrNull { it.optString("lang") == "en" }
                            ?.optString("value") ?: "No description"
                        val metrics = cveObj.optJSONObject("metrics")
                        val cvss = metrics?.let { m ->
                            m.optJSONArray("cvssMetricV31")?.optJSONObject(0)
                                ?.optJSONObject("cvssData")?.optDouble("baseScore", Double.NaN)
                                ?.takeIf { !it.isNaN() }
                                ?: m.optJSONArray("cvssMetricV30")?.optJSONObject(0)
                                    ?.optJSONObject("cvssData")?.optDouble("baseScore", Double.NaN)
                                    ?.takeIf { !it.isNaN() }
                                ?: m.optJSONArray("cvssMetricV2")?.optJSONObject(0)
                                    ?.optJSONObject("cvssData")?.optDouble("baseScore", Double.NaN)
                                    ?.takeIf { !it.isNaN() }
                        }
                        val published = cveObj.optString("published", "").take(10)
                        val refs = cveObj.optJSONArray("references")
                        val refList = (0 until minOf(refs?.length() ?: 0, 3))
                            .map { refs!!.getJSONObject(it).optString("url", "") }
                            .filter { it.isNotEmpty() }
                        CveResult(id = id, summary = summary, cvss = cvss, published = published, references = refList, source = "NVD")
                    }
                } catch (e: Exception) { emptyList() }

                if (nvdResults.isNotEmpty()) {
                    cveResults = nvdResults
                } else {
                    cveLookupError = "No CVEs found for \"$query\""
                }
            }
        } catch (e: Exception) {
            cveLookupError = "Could not reach CVE database. Check your connection."
        }
        cveLookupLoading = false
    }

    LazyColumn(
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()
    ) {
        item {
            Column {
                Text("TOOLS", fontSize = 22.sp, fontWeight = FontWeight.Bold, color = textColor, letterSpacing = 2.sp)
                Text("Security Testing Suite", fontSize = 12.sp, color = subtextColor)
            }
        }

        // Port Scanner
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("PORT SCANNER", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = targetIp,
                        onValueChange = { targetIp = it },
                        label = { Text("Target IP") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = textColor, unfocusedTextColor = textColor,
                            focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(presetGroups.keys.toList()) { preset ->
                            FilterChip(
                                selected = selectedPreset == preset && customFromPort.isEmpty(),
                                onClick = { selectedPreset = preset; customFromPort = ""; customToPort = "" },
                                label = { Text(preset, fontSize = 12.sp) }
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = customFromPort,
                            onValueChange = { customFromPort = it; if (it.isNotEmpty()) selectedPreset = null },
                            label = { Text("From port") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = textColor, unfocusedTextColor = textColor,
                                focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                            )
                        )
                        OutlinedTextField(
                            value = customToPort,
                            onValueChange = { customToPort = it; if (it.isNotEmpty()) selectedPreset = null },
                            label = { Text("To port") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = textColor, unfocusedTextColor = textColor,
                                focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                            )
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                if (!isPortScanning && isValidNetworkTarget(targetIp)) {
                                    isPortScanning = true
                                    portResults = emptyList()
                                    portScanProgress = 0f
                                    val ports = getPorts()
                                    val results = mutableListOf<Triple<Int, Boolean, String>>()
                                    val job = scope.launch {
                                        var done = 0
                                        ports.chunked(10).forEach { batch ->
                                            if (!isActive) return@forEach
                                            val batchResults = withContext(Dispatchers.IO) {
                                                coroutineScope {
                                                    batch.map { port ->
                                                        async {
                                                            val open = try {
                                                                val socket = java.net.Socket()
                                                                socket.connect(java.net.InetSocketAddress(targetIp, port), 500)
                                                                socket.close(); true
                                                            } catch (e: Exception) { false }
                                                            Triple(port, open, serviceNames[port] ?: "Unknown")
                                                        }
                                                    }.awaitAll()
                                                }
                                            }
                                            done += batch.size
                                            results.addAll(batchResults)
                                            portResults = results.sortedBy { it.first }
                                            portScanProgress = done.toFloat() / ports.size
                                        }
                                        isPortScanning = false
                                        scanJob = null
                                        val openPortNums = results.filter { it.second }.map { it.first }
                                        val histEntry = PortScanResult(targetIp, System.currentTimeMillis(), openPortNums)
                                        portScanHistory = (listOf(histEntry) + portScanHistory).take(3)
                                    }
                                    scanJob = job
                                }
                            },
                            enabled = !isPortScanning && isValidNetworkTarget(targetIp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                            shape = RoundedCornerShape(8.dp)
                        ) { Text("Scan", color = Color.White) }
                        if (isPortScanning) {
                            Button(
                                onClick = { scanJob?.cancel(); isPortScanning = false; portScanProgress = 0f },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFB71C1C)),
                                shape = RoundedCornerShape(8.dp)
                            ) { Text("Stop", color = Color.White) }
                        }
                    }
                    if (isPortScanning) {
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(
                            progress = { portScanProgress },
                            modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)),
                            color = Color(0xFF44FF88), trackColor = subtextColor.copy(alpha = 0.2f)
                        )
                    }
                    if (portResults.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        val openCount = portResults.count { it.second }
                        if (!isPortScanning) {
                            if (openCount == 0) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Filled.CheckCircle, null, tint = Color(0xFF44BB77), modifier = Modifier.size(20.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column {
                                        Text("Host appears secure", fontSize = 13.sp, color = Color(0xFF44BB77), fontWeight = FontWeight.Medium)
                                        Text("No open ports detected", fontSize = 11.sp, color = subtextColor)
                                    }
                                }
                            } else {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Filled.Warning, null, tint = Color(0xFFFF8844), modifier = Modifier.size(20.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column {
                                        Text("$openCount open port${if (openCount > 1) "s" else ""} found on $targetIp",
                                            fontSize = 13.sp,
                                            color = if (openCount > 5) Color(0xFFFF4444) else Color(0xFFFF8844),
                                            fontWeight = FontWeight.Medium)
                                        Text("Review open ports below", fontSize = 11.sp, color = subtextColor)
                                    }
                                }
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                        } else {
                            Text("$openCount open / ${portResults.size} scanned", fontSize = 12.sp, color = subtextColor)
                        }
                        Row(modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("${portResults.size} ports scanned", fontSize = 11.sp, color = subtextColor)
                            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                TextButton(onClick = { showAllPorts = !showAllPorts }) {
                                    Text(if (showAllPorts) "Open only" else "Show all", fontSize = 11.sp, color = Color(0xFF44FF88))
                                }
                                if (!isPortScanning) {
                                    TextButton(onClick = {
                                        val openPorts = portResults.filter { it.second }
                                        val report = buildString {
                                            appendLine("Port Scan Results")
                                            appendLine("Target: $targetIp")
                                            appendLine("Date: ${SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())}")
                                            appendLine()
                                            appendLine("Open Ports:")
                                            if (openPorts.isEmpty()) appendLine("None")
                                            else openPorts.forEach { (port, _, service) -> appendLine("  $port/$service") }
                                        }
                                        val shareIntent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                            type = "text/plain"
                                            putExtra(android.content.Intent.EXTRA_TEXT, report)
                                            putExtra(android.content.Intent.EXTRA_SUBJECT, "Port Scan Results - $targetIp")
                                        }
                                        context.startActivity(android.content.Intent.createChooser(shareIntent, "Share Results"))
                                    }) {
                                        Text("Share", fontSize = 11.sp, color = Color(0xFF44FF88))
                                    }
                                }
                            }
                        }
                        val displayed = if (showAllPorts) portResults else portResults.filter { it.second }
                        displayed.forEach { (port, open, service) ->
                            val portBadgeColor = when (port) {
                                22, 23, 3389 -> Color(0xFFB71C1C)
                                80, 443, 8080, 8443 -> Color(0xFF1565C0)
                                else -> Color(0xFFE65100)
                            }
                            val riskLabel = when (port) {
                                23, 3389 -> "HIGH RISK"
                                443, 22 -> "ENCRYPTED"
                                80, 8080 -> "WEB"
                                else -> "OPEN"
                            }
                            val riskColor = when (port) {
                                23, 3389 -> Color(0xFFFF4444)
                                443, 22 -> Color(0xFF44BB77)
                                80, 8080 -> Color(0xFF4488FF)
                                else -> Color(0xFFFF8844)
                            }
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                                    if (open) {
                                        Box(modifier = Modifier
                                            .background(portBadgeColor, RoundedCornerShape(4.dp))
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                        ) {
                                            Text("$port", fontSize = 11.sp, color = Color.White, fontWeight = FontWeight.Bold)
                                        }
                                        Spacer(modifier = Modifier.width(8.dp))
                                    }
                                    Text(service, fontSize = 13.sp,
                                        color = if (open) textColor else subtextColor,
                                        fontWeight = if (open) FontWeight.Bold else FontWeight.Normal)
                                    if (!open) {
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("($port)", fontSize = 11.sp, color = subtextColor)
                                    }
                                }
                                if (open) {
                                    Row(verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text(riskLabel, fontSize = 10.sp, color = riskColor, fontWeight = FontWeight.Bold)
                                        Icon(Icons.Filled.ContentCopy, null,
                                            modifier = Modifier.size(14.dp).clickable {
                                                val cb = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                                cb.setPrimaryClip(android.content.ClipData.newPlainText("port", "$targetIp:$port"))
                                                Toast.makeText(context, "$targetIp:$port copied", android.widget.Toast.LENGTH_SHORT).show()
                                            }, tint = subtextColor)
                                    }
                                } else {
                                    Text("closed", fontSize = 12.sp, color = subtextColor)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Ping Tool
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("PING", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = pingTarget,
                        onValueChange = { pingTarget = it },
                        label = { Text("IP or hostname") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = textColor, unfocusedTextColor = textColor,
                            focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = {
                            if (!isPinging && pingTarget.isNotEmpty()) {
                                isPinging = true
                                scope.launch {
                                    val start = System.currentTimeMillis()
                                    val reachable = try {
                                        withContext(Dispatchers.IO) { InetAddress.getByName(pingTarget).isReachable(2000) }
                                    } catch (e: Exception) { false }
                                    val elapsed = System.currentTimeMillis() - start
                                    val entry = Pair(pingTarget, if (reachable) elapsed else null)
                                    pingResults = (listOf(entry) + pingResults).take(5)
                                    isPinging = false
                                }
                            }
                        },
                        enabled = !isPinging && pingTarget.isNotEmpty(),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        if (isPinging) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = Color.White, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Pinging...", color = Color.White)
                        } else { Text("Ping", color = Color.White) }
                    }
                    if (defaultIp.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        OutlinedButton(
                            onClick = {
                                if (!isPinging) {
                                    pingTarget = defaultIp
                                    isPinging = true
                                    scope.launch {
                                        val start = System.currentTimeMillis()
                                        val reachable = try {
                                            withContext(Dispatchers.IO) { InetAddress.getByName(defaultIp).isReachable(2000) }
                                        } catch (e: Exception) { false }
                                        val elapsed = System.currentTimeMillis() - start
                                        pingResults = (listOf(Pair(defaultIp, if (reachable) elapsed else null)) + pingResults).take(5)
                                        isPinging = false
                                    }
                                }
                            },
                            enabled = !isPinging,
                            shape = RoundedCornerShape(8.dp)
                        ) { Text("Ping Gateway ($defaultIp)", fontSize = 12.sp) }
                    }
                    if (pingResults.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        val maxMs = pingResults.mapNotNull { it.second }.maxOrNull() ?: 1L
                        pingResults.forEach { (host, elapsed) ->
                            val msColor = when {
                                elapsed == null -> Color(0xFFFF4444)
                                elapsed < 50 -> Color(0xFF44BB77)
                                elapsed < 200 -> Color(0xFFFF8844)
                                else -> Color(0xFFFF4444)
                            }
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Text(host, fontSize = 11.sp, color = subtextColor, modifier = Modifier.width(100.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                if (elapsed != null) {
                                    val fraction = (elapsed.toFloat() / maxMs.coerceAtLeast(1).toFloat()).coerceIn(0.05f, 1f)
                                    Box(modifier = Modifier.weight(1f).height(14.dp).clip(RoundedCornerShape(3.dp))
                                        .background(subtextColor.copy(alpha = 0.1f))) {
                                        Box(modifier = Modifier.fillMaxHeight().fillMaxWidth(fraction)
                                            .clip(RoundedCornerShape(3.dp)).background(msColor))
                                    }
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text("${elapsed}ms", fontSize = 11.sp, color = msColor, modifier = Modifier.width(52.dp))
                                } else {
                                    Box(modifier = Modifier.weight(1f))
                                    Text("Unreachable", fontSize = 11.sp, color = msColor)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Port Scan History
        if (portScanHistory.isNotEmpty()) {
            item {
                Card(modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = cardColor),
                    shape = RoundedCornerShape(16.dp),
                    elevation = CardDefaults.cardElevation(4.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("RECENT SCANS", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        portScanHistory.forEachIndexed { idx, result ->
                            val isExpanded = expandedHistoryIndex == idx
                            Column(modifier = Modifier.fillMaxWidth()
                                .clickable { expandedHistoryIndex = if (isExpanded) null else idx }
                                .padding(vertical = 4.dp)
                            ) {
                                Row(modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column {
                                        Text(result.ip, fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                                        Text("${result.openPorts.size} open ports · ${getTimeAgo(result.timestamp)}",
                                            fontSize = 11.sp, color = subtextColor)
                                    }
                                    Icon(
                                        if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                        null, tint = subtextColor, modifier = Modifier.size(18.dp)
                                    )
                                }
                                if (isExpanded && result.openPorts.isNotEmpty()) {
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(result.openPorts.joinToString(", "), fontSize = 12.sp, color = Color(0xFF44FF88))
                                }
                            }
                            if (idx < portScanHistory.size - 1) {
                                HorizontalDivider(color = subtextColor.copy(alpha = 0.1f))
                            }
                        }
                    }
                }
            }
        }

        // WHOIS Lookup
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("WHOIS LOOKUP", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = whoisTarget,
                        onValueChange = { whoisTarget = it },
                        label = { Text("Domain or IP") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = textColor, unfocusedTextColor = textColor,
                            focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = { scope.launch { doWhoisLookup(whoisTarget.trim()) } },
                        enabled = !isWhoisLoading && whoisTarget.isNotEmpty(),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        if (isWhoisLoading) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = Color.White, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Looking up...", color = Color.White)
                        } else { Text("Lookup", color = Color.White) }
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = {
                                if (!isWhoisLoading) {
                                    scope.launch {
                                        try {
                                            val myIp = withContext(Dispatchers.IO) {
                                                val url = java.net.URL("https://api.ipify.org")
                                                val conn = url.openConnection() as java.net.HttpURLConnection
                                                conn.connectTimeout = 5000; conn.readTimeout = 5000
                                                try { conn.inputStream.bufferedReader().readText().trim() } finally { conn.disconnect() }
                                            }
                                            doWhoisLookup(myIp)
                                        } catch (e: Exception) {
                                            whoisError = "Could not fetch public IP"
                                        }
                                    }
                                }
                            },
                            enabled = !isWhoisLoading,
                            shape = RoundedCornerShape(8.dp)
                        ) { Text("My IP", fontSize = 12.sp) }
                        if (defaultIp.isNotEmpty()) {
                            OutlinedButton(
                                onClick = {
                                    if (!isWhoisLoading) {
                                        whoisTarget = defaultIp
                                        scope.launch { doWhoisLookup(defaultIp) }
                                    }
                                },
                                enabled = !isWhoisLoading,
                                shape = RoundedCornerShape(8.dp)
                            ) { Text("Gateway", fontSize = 12.sp) }
                        }
                        OutlinedButton(
                            onClick = {
                                if (!isWhoisLoading) {
                                    whoisTarget = "8.8.8.8"
                                    scope.launch { doWhoisLookup("8.8.8.8") }
                                }
                            },
                            enabled = !isWhoisLoading,
                            shape = RoundedCornerShape(8.dp)
                        ) { Text("8.8.8.8", fontSize = 12.sp) }
                    }
                    if (whoisError.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(whoisError, fontSize = 12.sp, color = Color(0xFFFF4444))
                    }
                    whoisResult?.let { result ->
                        Spacer(modifier = Modifier.height(8.dp))
                        result.forEach { (label, value) ->
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(label, fontSize = 12.sp, color = subtextColor, modifier = Modifier.weight(0.4f))
                                Row(modifier = Modifier.weight(0.6f),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.End
                                ) {
                                    Text(value, fontSize = 12.sp, color = textColor, fontWeight = FontWeight.Medium,
                                        modifier = Modifier.weight(1f), maxLines = 1,
                                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Icon(Icons.Filled.ContentCopy, null,
                                        modifier = Modifier.size(14.dp).clickable {
                                            val cb = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                            cb.setPrimaryClip(android.content.ClipData.newPlainText(label, value))
                                            Toast.makeText(context, "$label copied", android.widget.Toast.LENGTH_SHORT).show()
                                        }, tint = subtextColor)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Traceroute
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("TRACEROUTE", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = traceTarget,
                        onValueChange = { traceTarget = it },
                        label = { Text("Target IP or hostname") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = textColor, unfocusedTextColor = textColor,
                            focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                        )
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                if (!isTracing && isValidNetworkTarget(traceTarget.trim())) {
                                    isTracing = true
                                    traceResults = emptyList()
                                    val target = traceTarget.trim()
                                    val job = scope.launch {
                                        for (hop in 1..15) {
                                            if (!isActive) break
                                            val start = System.currentTimeMillis()
                                            try {
                                                withContext(Dispatchers.IO) {
                                                    java.net.Socket().use { socket ->
                                                        socket.soTimeout = 1000
                                                        socket.connect(java.net.InetSocketAddress(target, 80), 1000)
                                                    }
                                                }
                                                val ms = System.currentTimeMillis() - start
                                                withContext(Dispatchers.Main) {
                                                    traceResults = traceResults + TraceHop(hop, target, ms, false)
                                                }
                                                break
                                            } catch (e: java.net.SocketTimeoutException) {
                                                withContext(Dispatchers.Main) {
                                                    traceResults = traceResults + TraceHop(hop, "*", 0, true)
                                                }
                                            } catch (e: Exception) {
                                                val ms = System.currentTimeMillis() - start
                                                withContext(Dispatchers.Main) {
                                                    traceResults = traceResults + TraceHop(hop, target, ms, false)
                                                }
                                                break
                                            }
                                        }
                                        isTracing = false
                                        traceJob = null
                                    }
                                    traceJob = job
                                }
                            },
                            enabled = !isTracing && isValidNetworkTarget(traceTarget.trim()),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                            shape = RoundedCornerShape(8.dp)
                        ) { Text("Trace", color = Color.White) }
                        if (isTracing) {
                            Button(
                                onClick = { traceJob?.cancel(); isTracing = false },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFB71C1C)),
                                shape = RoundedCornerShape(8.dp)
                            ) { Text("Stop", color = Color.White) }
                        }
                    }
                    if (isTracing) {
                        Spacer(modifier = Modifier.height(8.dp))
                        LinearProgressIndicator(
                            modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)),
                            color = Color(0xFF44FF88), trackColor = subtextColor.copy(alpha = 0.2f)
                        )
                    }
                    if (traceResults.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        traceResults.forEach { hop ->
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Text("${hop.hop}", fontSize = 12.sp, color = subtextColor, modifier = Modifier.width(24.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(if (hop.timedOut) "* * *" else hop.ip, fontSize = 12.sp, color = textColor, modifier = Modifier.weight(1f))
                                if (!hop.timedOut) {
                                    val msColor = when {
                                        hop.ms < 50 -> Color(0xFF44BB77)
                                        hop.ms < 200 -> Color(0xFFFF8844)
                                        else -> Color(0xFFFF4444)
                                    }
                                    Text("${hop.ms}ms", fontSize = 12.sp, color = msColor)
                                } else {
                                    Text("timeout", fontSize = 12.sp, color = subtextColor)
                                }
                            }
                        }
                        if (!isTracing) {
                            Spacer(modifier = Modifier.height(8.dp))
                            val allTimedOut = traceResults.all { it.timedOut }
                            val summaryText = if (allTimedOut) {
                                "Host unreachable or ICMP blocked"
                            } else {
                                val hopCount = traceResults.count { !it.timedOut }
                                val totalMs = traceResults.filter { !it.timedOut }.sumOf { it.ms }
                                "$hopCount hops to destination \u2022 Total time: ${totalMs}ms"
                            }
                            Text(summaryText, fontSize = 12.sp,
                                color = if (allTimedOut) Color(0xFFFF8844) else Color(0xFF44BB77),
                                fontWeight = FontWeight.Medium)
                            Spacer(modifier = Modifier.height(4.dp))
                            TextButton(onClick = {
                                val report = buildString {
                                    appendLine("Traceroute Results")
                                    appendLine("Target: $traceTarget")
                                    appendLine("Date: ${SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())}")
                                    appendLine()
                                    traceResults.forEach { h ->
                                        appendLine("${h.hop}  ${if (h.timedOut) "* * *" else "${h.ip}  ${h.ms}ms"}")
                                    }
                                }
                                val shareIntent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(android.content.Intent.EXTRA_TEXT, report)
                                    putExtra(android.content.Intent.EXTRA_SUBJECT, "Traceroute - $traceTarget")
                                }
                                context.startActivity(android.content.Intent.createChooser(shareIntent, "Share Results"))
                            }) {
                                Text("Share", fontSize = 11.sp, color = Color(0xFF44FF88))
                            }
                        }
                    }
                }
            }
        }

        // CVE Lookup
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("CVE LOOKUP", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = cveLookupQuery,
                        onValueChange = { cveLookupQuery = it },
                        label = { Text("e.g. 192.168.1.1, netgear, apache") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = textColor, unfocusedTextColor = textColor,
                            focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                        )
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Search by vendor or product name (e.g. netgear, apache, openssl)", fontSize = 12.sp, color = subtextColor)
                    val cveChipDevices = devices.filter { device ->
                        val mfr = device.manufacturer
                        mfr != "Unknown" && mfr.length > 2 && !mfr.contains(Regex("[A-Z0-9_-]{6,}"))
                    }.take(5)
                    if (cveChipDevices.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(cveChipDevices) { device ->
                                val chipLabel = device.manufacturer.take(30)
                                FilterChip(
                                    selected = false,
                                    onClick = { cveLookupQuery = chipLabel.lowercase() },
                                    label = { Text(chipLabel, fontSize = 11.sp) }
                                )
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = { scope.launch { doCveLookup(cveLookupQuery) } },
                        enabled = !cveLookupLoading && cveLookupQuery.isNotEmpty(),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                        shape = RoundedCornerShape(8.dp)
                    ) { Text("Search CVEs", color = Color.White) }
                    if (cveLookupLoading) {
                        Spacer(modifier = Modifier.height(12.dp))
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), color = Color(0xFF44FF88), strokeWidth = 2.dp)
                    }
                    cveLookupError?.let { err ->
                        Spacer(modifier = Modifier.height(8.dp))
                        val looksLikeSsid = cveLookupQuery.matches(Regex("[A-Z0-9_\\-]{4,}"))
                        val helpText = if (looksLikeSsid)
                            "Tip: Search by manufacturer name, not network name (e.g. try 'netgear' instead of '$cveLookupQuery')"
                        else
                            "No CVEs found for '$cveLookupQuery'. Try a shorter vendor name."
                        Text(helpText, fontSize = 12.sp, color = subtextColor)
                    }
                    if (cveResults.isEmpty() && !cveLookupLoading && cveLookupError == null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Enter a vendor or product name to search CVEs", fontSize = 12.sp, color = subtextColor)
                    }
                    if (cveResults.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("${cveResults.size} result(s)", fontSize = 11.sp, color = subtextColor)
                        Spacer(modifier = Modifier.height(4.dp))
                        cveResults.forEach { cve ->
                            val (severityLabel, severityColor) = getCveSeverity(cve.cvss)
                            var expanded by remember { mutableStateOf(false) }
                            Column(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp).clickable { expanded = !expanded }) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(cve.id, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp, color = textColor, modifier = Modifier.weight(1f))
                                    Text("via ${cve.source}", fontSize = 10.sp, color = subtextColor, modifier = Modifier.padding(end = 6.dp))
                                    Surface(color = severityColor.copy(alpha = 0.15f), shape = RoundedCornerShape(4.dp)) {
                                        Text(severityLabel, fontSize = 10.sp, color = severityColor,
                                            fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                    }
                                }
                                cve.cvss?.let {
                                    Text("CVSS: ${"%.1f".format(it)}", fontSize = 11.sp, color = subtextColor)
                                }
                                Text(
                                    if (expanded) cve.summary else cve.summary.take(120) + if (cve.summary.length > 120) "…" else "",
                                    fontSize = 12.sp, color = subtextColor, modifier = Modifier.padding(top = 2.dp)
                                )
                                if (cve.published.isNotEmpty()) {
                                    Text("Published: ${cve.published.take(10)}", fontSize = 11.sp, color = subtextColor)
                                }
                            }
                            Divider(color = subtextColor.copy(alpha = 0.15f))
                        }
                    }
                }
            }
        }

        // Python Scanner
        item {
            Card(modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("PYTHON SCANNER", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp,
                            modifier = Modifier.weight(1f))
                        Surface(color = Color(0xFF44FF88).copy(alpha = 0.15f), shape = RoundedCornerShape(4.dp)) {
                            Text("Chaquopy", fontSize = 10.sp, color = Color(0xFF44FF88), fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                        }
                        if (RootFeatureGate.canUseRootFeatures()) {
                            Spacer(modifier = Modifier.width(4.dp))
                            Surface(color = Color(0xFFFF4444).copy(alpha = 0.15f), shape = RoundedCornerShape(4.dp)) {
                                Text("nmap", fontSize = 10.sp, color = Color(0xFFFF4444), fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        if (RootFeatureGate.canUseRootFeatures()) "Using nmap — full scan capabilities"
                        else "Using TCP scanner — no root required",
                        fontSize = 11.sp, color = subtextColor
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("Host Scan", "Service Scan").forEachIndexed { idx, label ->
                            val selected = pythonScanTab == idx
                            Surface(
                                color = if (selected) Color(0xFF1565C0) else subtextColor.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.clickable { onPythonScanTabChange(idx) }
                            ) {
                                Text(label, fontSize = 12.sp,
                                    color = if (selected) Color.White else subtextColor,
                                    fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(10.dp))

                    if (pythonScanTab == 0) {
                        OutlinedTextField(
                            value = nmapTarget,
                            onValueChange = { onNmapTargetChange(it) },
                            label = { Text("Target IP or CIDR (e.g. 192.168.1.0/24)") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = textColor, unfocusedTextColor = textColor,
                                focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                            )
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = { onLaunchHostScan() },
                            enabled = !nmapLoading && nmapTarget.isNotEmpty(),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                            shape = RoundedCornerShape(8.dp)
                        ) { Text("Scan", color = Color.White) }
                        if (nmapLoading) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.size(20.dp), color = Color(0xFF44FF88), strokeWidth = 2.dp)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Running TCP scan... this may take 10-30s", fontSize = 12.sp, color = subtextColor)
                            }
                        }
                        nmapError?.let { err ->
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(err, fontSize = 12.sp, color = Color(0xFFFF8844))
                        }
                        nmapResults?.let { result ->
                            if (result.success) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text("${result.hosts.size} host(s) found", fontSize = 11.sp, color = subtextColor)
                                result.hosts.forEach { host ->
                                    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                        verticalAlignment = Alignment.CenterVertically) {
                                        val dotColor = if (host.state == "up") Color(0xFF44BB77) else Color(0xFF888888)
                                        Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(dotColor))
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(host.ip, fontSize = 13.sp, color = textColor, fontFamily = FontFamily.Monospace)
                                            if (host.hostname.isNotEmpty()) Text(host.hostname, fontSize = 11.sp, color = subtextColor)
                                        }
                                        Text(host.state, fontSize = 11.sp, color = dotColor)
                                    }
                                }
                            }
                        }
                    } else {
                        OutlinedTextField(
                            value = serviceTarget,
                            onValueChange = { onServiceTargetChange(it) },
                            label = { Text("Target IP") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = textColor, unfocusedTextColor = textColor,
                                focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                            )
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        val presets = listOf(
                            "Common" to "22,80,443,8080,8443",
                            "Web" to "80,443,8080,8443,3000,8000",
                            "Database" to "3306,5432,6379,27017",
                            "Custom" to ""
                        )
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            items(presets.size) { idx ->
                                val (label, ports) = presets[idx]
                                FilterChip(
                                    selected = servicePortPreset == idx,
                                    onClick = {
                                        servicePortPreset = idx
                                        if (ports.isNotEmpty()) servicePorts = ports
                                    },
                                    label = { Text(label, fontSize = 11.sp) }
                                )
                            }
                        }
                        if (servicePortPreset == 3) {
                            Spacer(modifier = Modifier.height(6.dp))
                            OutlinedTextField(
                                value = servicePorts,
                                onValueChange = { servicePorts = it },
                                label = { Text("Ports (comma-separated)") },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedTextColor = textColor, unfocusedTextColor = textColor,
                                    focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                                )
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = { onLaunchServiceScan(servicePorts) },
                            enabled = !serviceLoading && serviceTarget.isNotEmpty(),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF1565C0)),
                            shape = RoundedCornerShape(8.dp)
                        ) { Text("Scan", color = Color.White) }
                        if (serviceLoading) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.size(20.dp), color = Color(0xFF44FF88), strokeWidth = 2.dp)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("Scanning services via TCP... this may take 20-60s", fontSize = 12.sp, color = subtextColor)
                            }
                        }
                        serviceError?.let { err ->
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(err, fontSize = 12.sp, color = Color(0xFFFF8844))
                            Text("Try adjusting target or port range and retry", fontSize = 11.sp, color = subtextColor)
                        }
                        serviceResults?.let { result ->
                            if (result.success) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text("${result.services.size} service(s) on ${result.host}", fontSize = 11.sp, color = subtextColor)
                                result.services.forEach { svc ->
                                    val stateColor = when (svc.state) {
                                        "open" -> Color(0xFFFF4444)
                                        "filtered" -> Color(0xFFFFAA44)
                                        else -> Color(0xFF888888)
                                    }
                                    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                                        verticalAlignment = Alignment.CenterVertically) {
                                        Text("${svc.port}/${svc.protocol}", fontSize = 12.sp,
                                            color = textColor, fontFamily = FontFamily.Monospace, modifier = Modifier.width(80.dp))
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(svc.service.ifEmpty { "unknown" }, fontSize = 12.sp, color = textColor)
                                            if (svc.version.isNotEmpty() || svc.product.isNotEmpty()) {
                                                Text("${svc.product} ${svc.version}".trim(), fontSize = 11.sp, color = subtextColor)
                                            }
                                        }
                                        Surface(color = stateColor.copy(alpha = 0.15f), shape = RoundedCornerShape(4.dp)) {
                                            Text(svc.state, fontSize = 10.sp, color = stateColor,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                                        }
                                    }
                                    Divider(color = subtextColor.copy(alpha = 0.1f))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
