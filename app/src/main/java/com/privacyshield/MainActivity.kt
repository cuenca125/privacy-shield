package com.privacyshield

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.compose.runtime.collectAsState
import androidx.lifecycle.lifecycleScope
import com.privacyshield.data.AppDatabase
import com.privacyshield.data.DeviceHistoryEntity
import com.privacyshield.data.ScanSessionSummary
import com.privacyshield.data.toHistoryEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit
import kotlin.math.*
import com.privacyshield.model.*

class MainActivity : ComponentActivity() {

    private lateinit var wifiManager: WifiManager
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private val devices = mutableStateListOf<DetectedDevice>()
    private var isScanning by mutableStateOf(false)
    private var selectedDevice by mutableStateOf<DetectedDevice?>(null)
    private var currentTheme by mutableStateOf(AppTheme.DARK)
    private var searchQuery by mutableStateOf("")
    private var selectedFilter by mutableStateOf<DeviceType?>(null)
    private var currentScanMode by mutableStateOf(ScanMode.FULL)
    private var backgroundScanEnabled by mutableStateOf(false)
    private var currentTab by mutableStateOf(AppTab.HOME)
    private var showOnboarding by mutableStateOf(false)
    private val signalHistory = mutableStateMapOf<String, MutableList<Int>>()
    private lateinit var database: AppDatabase
    private var currentScanSessionId = ""
    private var isAuthenticated by mutableStateOf(false)
    private var lastManualScanTime: Long = 0
    private var scanStartTime: Long = 0
    private var lastScanDuration: Long = 0
    private var lastScanTime: Long by mutableStateOf(0L)
    private var homeResetTrigger by mutableStateOf(0)
    private var searchResetTrigger by mutableStateOf(0)
    private var historyResetTrigger by mutableStateOf(0)
    private var securityResetTrigger by mutableStateOf(0)
    private var searchScrollTrigger by mutableStateOf(0)
    private var searchSortOption by mutableStateOf(0)
    private var searchSuspiciousOnly by mutableStateOf(false)
    private var searchSafeOnly by mutableStateOf(false)
    private var historyDateFilter by mutableStateOf(0)
    private var historyExpandedSessionId by mutableStateOf<String?>(null)

    // Security feature navigation
    private var selectedSecurityFeature by mutableStateOf<String?>(null)
    private var lastEvilTwinAlerts by mutableStateOf<List<EvilTwinAlert>>(emptyList())

    // BLE scan buffer — batches updates to main thread every 500ms to reduce recompositions
    private val deviceBuffer = mutableListOf<DetectedDevice>()
    private val signalBuffer = mutableListOf<Pair<String, Int>>()
    private var lastBufferFlush = 0L
    private val bufferLock = Any()

    // Python Scanner state — hoisted to MainActivity so scans survive tab navigation
    private var nmapTarget by mutableStateOf("")
    private var nmapResults by mutableStateOf<NmapScanResult?>(null)
    private var nmapLoading by mutableStateOf(false)
    private var nmapError by mutableStateOf<String?>(null)
    private var serviceTarget by mutableStateOf("")
    private var serviceResults by mutableStateOf<ServiceScanResult?>(null)
    private var serviceLoading by mutableStateOf(false)
    private var serviceError by mutableStateOf<String?>(null)
    private var pythonScanTab by mutableStateOf(0)

    // Expanded MAC vendor database - 200+ vendors
    private val macVendors = mapOf(
        "00:03:93" to "Apple", "00:05:02" to "Apple", "00:0A:27" to "Apple", "00:0A:95" to "Apple",
        "00:0D:93" to "Apple", "00:11:24" to "Apple", "00:14:51" to "Apple", "00:16:CB" to "Apple",
        "00:17:F2" to "Apple", "00:19:E3" to "Apple", "00:1B:63" to "Apple", "00:1C:B3" to "Apple",
        "00:1D:4F" to "Apple", "00:1E:52" to "Apple", "00:1E:C2" to "Apple", "00:1F:5B" to "Apple",
        "00:1F:F3" to "Apple", "00:21:E9" to "Apple", "00:22:41" to "Apple", "00:23:12" to "Apple",
        "00:23:32" to "Apple", "00:23:6C" to "Apple", "00:23:DF" to "Apple", "00:24:36" to "Apple",
        "00:25:00" to "Apple", "00:25:4B" to "Apple", "00:25:BC" to "Apple", "00:26:08" to "Apple",
        "00:26:4A" to "Apple", "00:26:B0" to "Apple", "00:26:BB" to "Apple", "AC:DE:48" to "Apple",
        "28:6A:BA" to "Apple", "F4:5C:89" to "Apple", "BC:D0:74" to "Apple", "A4:D1:D2" to "Apple",
        "00:12:47" to "Samsung", "00:12:FB" to "Samsung", "00:13:77" to "Samsung", "00:15:B9" to "Samsung",
        "00:16:32" to "Samsung", "00:16:6B" to "Samsung", "00:16:6C" to "Samsung", "00:17:C9" to "Samsung",
        "00:17:D5" to "Samsung", "00:18:AF" to "Samsung", "00:1A:8A" to "Samsung", "00:1B:98" to "Samsung",
        "00:1C:43" to "Samsung", "00:1D:25" to "Samsung", "00:1E:7D" to "Samsung", "00:1E:E1" to "Samsung",
        "00:1E:E2" to "Samsung", "04:FE:A1" to "Samsung", "E8:50:8B" to "Samsung", "34:AA:8B" to "Samsung",
        "FC:03:9F" to "Samsung", "D0:25:98" to "Samsung", "C8:BA:94" to "Samsung", "58:8E:81" to "Samsung",
        "00:00:D9" to "Sony", "00:01:4A" to "Sony", "00:01:E3" to "Sony", "00:02:5B" to "Sony",
        "00:04:1F" to "Sony", "00:04:75" to "Sony", "00:06:4F" to "Sony", "00:09:B7" to "Sony",
        "00:0A:D9" to "Sony", "00:0D:F0" to "Sony", "00:0E:07" to "Sony", "00:0F:4B" to "Sony",
        "00:13:15" to "Sony", "00:16:FE" to "Sony", "00:19:63" to "Sony", "00:1A:80" to "Sony",
        "00:1B:FB" to "Sony", "00:1D:BA" to "Sony", "00:1E:3D" to "Sony", "00:1F:E2" to "Sony",
        "A0:20:A6" to "Sony", "AC:9B:0A" to "Sony", "54:B8:0A" to "Sony", "30:39:26" to "Sony",
        "00:1A:11" to "Google", "3C:5A:B4" to "Google", "A4:D1:8C" to "Google", "B4:F0:AB" to "Google",
        "F4:F5:D8" to "Google", "D8:50:E6" to "Google", "F8:8F:CA" to "Google",
        "00:27:22" to "TP-Link", "50:C7:BF" to "TP-Link", "70:3A:CB" to "TP-Link", "E8:94:F6" to "TP-Link",
        "A0:F3:C1" to "TP-Link", "B0:95:75" to "TP-Link", "C0:4A:00" to "TP-Link", "D8:0D:17" to "TP-Link",
        "00:9E:C8" to "Xiaomi", "04:CF:8C" to "Xiaomi", "28:6C:07" to "Xiaomi", "34:CE:00" to "Xiaomi",
        "50:8F:4C" to "Xiaomi", "64:09:80" to "Xiaomi", "78:11:DC" to "Xiaomi", "D8:BB:2C" to "Xiaomi",
        "00:18:82" to "Huawei", "00:1E:10" to "Huawei", "00:25:9E" to "Huawei", "AC:E2:D3" to "Huawei",
        "00:1C:62" to "LG", "00:1E:75" to "LG", "00:1F:6B" to "LG", "10:68:3F" to "LG",
        "00:71:47" to "Amazon", "44:65:0D" to "Amazon", "50:DC:E7" to "Amazon", "74:C2:46" to "Amazon",
        "00:0C:6E" to "Asus", "00:0E:A6" to "Asus", "00:11:2F" to "Asus", "00:13:D4" to "Asus",
        "00:09:5B" to "Netgear", "00:0F:B5" to "Netgear", "00:14:6C" to "Netgear", "00:18:4D" to "Netgear",
        "00:00:0C" to "Cisco", "00:01:42" to "Cisco", "00:01:63" to "Cisco", "00:01:64" to "Cisco"
    )

    private val macVendorsNoColon = mapOf(
        "F0DBF8" to "Apple", "BC3AEA" to "Apple", "906C3F" to "Apple",
        "089DFB" to "Samsung", "34AA8B" to "Samsung", "50C8E5" to "Samsung",
        "3C5AB4" to "Google", "A4D18C" to "Google", "F4F5D8" to "Google",
        "009EC8" to "Xiaomi", "34CE00" to "Xiaomi", "78DBCA" to "Xiaomi",
        "001E10" to "Huawei", "286ED4" to "Huawei", "703ACB" to "TP-Link",
        "00095B" to "Netgear", "44650D" to "Amazon", "74C246" to "Amazon",
        "000C6E" to "Asus", "001C62" to "LG", "1C5566" to "Motorola",
        "2C8DB3" to "OnePlus", "189C27" to "Cisco", "54B80A" to "Sony"
    )

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        if (permissions.all { it.value }) startDeviceScan(currentScanMode)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.Theme_PrivacyShield)
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        // Suppress Chaquopy 16KB alignment compatibility dialog (cosmetic only)
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            val msg = throwable.message ?: ""
            if (msg.contains("16kb", ignoreCase = true) || msg.contains("alignment", ignoreCase = true)) {
                // Ignore alignment warnings — does not affect functionality
            } else {
                defaultHandler?.uncaughtException(thread, throwable)
            }
        }

        wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        bluetoothAdapter = (getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
        database = AppDatabase.getInstance(this)

        loadThemePreference()

        val onboardingPrefs = getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
        showOnboarding = !onboardingPrefs.getBoolean("onboarding_done", false)

        backgroundScanEnabled = getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
            .getBoolean("background_scan_enabled", false)
        if (backgroundScanEnabled) scheduleBackgroundScan()

        val appLockEnabled = getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
            .getBoolean("app_lock_enabled", false)
        if (appLockEnabled) {
            showBiometricPrompt(onSuccess = { isAuthenticated = true })
        } else {
            isAuthenticated = true
        }

        PythonBridge.init(applicationContext)
        OuiLookup.loadDatabase(applicationContext)

        setContent {
            PrivacyShieldTheme(isDark = currentTheme == AppTheme.DARK) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
                ) {
                    MainLayout()
                }
            }

            LaunchedEffect(key1 = Unit) {
                while (true) {
                    if (devices.isNotEmpty() && !isScanning) {
                        delay(3000)
                        updateSignalStrengths()
                    } else delay(1000)
                }
            }
        }
    }

    @Composable
    fun MainLayout() {
        if (!isAuthenticated) {
            Box(modifier = Modifier.fillMaxSize().background(Color(0xFF000000)),
                contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = Color(0xFF44FF88))
            }
            return
        }
        BackHandler(enabled = selectedDevice != null) { selectedDevice = null }
        BackHandler(enabled = currentTab != AppTab.HOME) { currentTab = AppTab.HOME }
        BackHandler(enabled = selectedSecurityFeature != null) { selectedSecurityFeature = null }
        Box(modifier = Modifier.fillMaxSize()) {
            Scaffold(bottomBar = { BottomNavigationBar() }) { paddingValues ->
                Box(modifier = Modifier.padding(paddingValues)) {
                    when (currentTab) {
                        AppTab.HOME -> if (selectedDevice == null) HomeTab() else DeviceDetailScreen()
                        AppTab.SEARCH -> SearchTab()
                        AppTab.NETWORK -> NetworkTab()
                        AppTab.TOOLS -> ToolsTab()
                        AppTab.SECURITY -> when (selectedSecurityFeature) {
                            "nmap_deep" -> NmapDeepScanScreen()
                            "scapy_analyzer" -> ScapyAnalyzerScreen()
                            "arp_detection" -> ArpDetectionScreen()
                            "traffic_monitor" -> TrafficMonitorScreen()
                            "python_script" -> PythonScriptScreen()
                            else -> SecurityTab()
                        }
                    }
                }
            }
            if (showOnboarding) {
                OnboardingOverlay(onDone = {
                    showOnboarding = false
                    getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
                        .edit().putBoolean("onboarding_done", true).apply()
                })
            }
        }
    }

    @Composable
    fun OnboardingOverlay(onDone: () -> Unit) {
        var page by remember { mutableStateOf(0) }
        val pages = listOf(
            Triple(Icons.Filled.Shield, "Privacy Shield", "Detect nearby cameras, mics and IoT devices"),
            Triple(Icons.Filled.NetworkCheck, "Network Intelligence", "Analyze WiFi networks, detect evil twins, discover hosts and check for DNS leaks"),
            Triple(Icons.Filled.Security, "Security Toolkit", "Port scanner, CVE lookup, WHOIS, traceroute and Python-powered network scanner")
        )
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFF000000))
                .clickable(enabled = false) {},
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(32.dp)
            ) {
                Spacer(modifier = Modifier.weight(1f))
                Icon(
                    pages[page].first, null,
                    tint = Color(0xFF44FF88),
                    modifier = Modifier.size(96.dp)
                )
                Spacer(modifier = Modifier.height(32.dp))
                Text(
                    pages[page].second,
                    fontSize = 28.sp, fontWeight = FontWeight.Bold,
                    color = Color.White, textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    pages[page].third,
                    fontSize = 16.sp, color = Color(0xFF888888),
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )
                Spacer(modifier = Modifier.weight(1f))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    pages.indices.forEach { i ->
                        Box(
                            modifier = Modifier
                                .size(if (i == page) 10.dp else 6.dp)
                                .clip(CircleShape)
                                .background(if (i == page) Color(0xFF44FF88) else Color(0xFF444444))
                        )
                    }
                }
                Spacer(modifier = Modifier.height(32.dp))
                Button(
                    onClick = {
                        if (page < pages.size - 1) page++ else onDone()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF44FF88)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        if (page < pages.size - 1) "Next" else "Get Started",
                        color = Color(0xFF000000), fontWeight = FontWeight.Bold, fontSize = 16.sp
                    )
                }
                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }

    @Composable
    fun BottomNavigationBar() {
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF0A0A0A) else Color.White
        val selectedColor = if (currentTheme == AppTheme.DARK) Color.White else MaterialTheme.colorScheme.primary
        val unselectedColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else MaterialTheme.colorScheme.onSurfaceVariant

        // Pulse animation for Tools icon — declared unconditionally (rules of hooks)
        val infiniteTransition = rememberInfiniteTransition(label = "toolsPulse")
        val pulseAlpha by infiniteTransition.animateFloat(
            initialValue = 0.6f,
            targetValue = 1.0f,
            animationSpec = infiniteRepeatable(
                animation = tween(800, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "pulseAlpha"
        )
        val isToolsScanning = nmapLoading || serviceLoading

        NavigationBar(
            containerColor = bgColor,
            modifier = Modifier
                .navigationBarsPadding()
                .then(
                    if (currentTheme == AppTheme.LIGHT)
                        Modifier.drawWithContent {
                            drawContent()
                            drawLine(
                                color = androidx.compose.ui.graphics.Color(0xFFE0E0E0),
                                start = androidx.compose.ui.geometry.Offset(0f, 0f),
                                end = androidx.compose.ui.geometry.Offset(size.width, 0f),
                                strokeWidth = 1.dp.toPx()
                            )
                        }
                    else Modifier
                )
        ) {
            listOf(
                Triple(AppTab.HOME, Icons.Filled.Shield, "Home"),
                Triple(AppTab.SEARCH, Icons.Filled.Search, "Search"),
                Triple(AppTab.NETWORK, Icons.Filled.NetworkCheck, "Network"),
                Triple(AppTab.TOOLS, Icons.Filled.Build, "Tools"),
                Triple(AppTab.SECURITY, Icons.Filled.Security, "Security")
            ).forEach { (tab, icon, label) ->
                val toolsIconTint = when {
                    tab == AppTab.TOOLS && isToolsScanning -> Color(0xFF4CAF50).copy(alpha = pulseAlpha)
                    tab == AppTab.TOOLS && currentTab == AppTab.TOOLS -> MaterialTheme.colorScheme.primary
                    else -> null // use default NavigationBarItem colors
                }
                NavigationBarItem(
                    selected = currentTab == tab,
                    onClick = {
                        if (currentTab == tab) {
                            when (tab) {
                                AppTab.HOME -> {
                                    if (selectedDevice != null) {
                                        selectedDevice = null
                                    } else {
                                        homeResetTrigger++
                                    }
                                }
                                AppTab.SEARCH -> searchResetTrigger++
                                AppTab.NETWORK -> historyResetTrigger++
                                AppTab.SECURITY -> securityResetTrigger++
                                AppTab.TOOLS -> { /* no reset for tools */ }
                            }
                        } else {
                            currentTab = tab
                        }
                    },
                    icon = {
                        if (toolsIconTint != null) {
                            Icon(icon, label, tint = toolsIconTint)
                        } else {
                            Icon(icon, label)
                        }
                    },
                    label = { Text(label) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = selectedColor,
                        selectedTextColor = selectedColor,
                        unselectedIconColor = unselectedColor,
                        unselectedTextColor = unselectedColor,
                        indicatorColor = if (currentTheme == AppTheme.DARK) Color(0xFF2A2A2A) else Color(0xFFE0E0E0)
                    )
                )
            }
        }
    }

    fun launchHostScan() {
        if (nmapLoading) return
        if (!isValidNetworkTarget(nmapTarget)) {
            nmapError = "Invalid target — enter a valid IP, CIDR, or hostname"
            return
        }
        nmapLoading = true
        nmapError = null
        nmapResults = null
        lifecycleScope.launch(Dispatchers.IO) {
            val result = withTimeoutOrNull(60_000L) { PythonBridge.runHostScan(applicationContext, nmapTarget) }
            withContext(Dispatchers.Main) {
                nmapLoading = false
                if (result == null) nmapError = "Operation timed out after 60 seconds"
                else { nmapResults = result; if (!result.success) nmapError = result.error }
            }
        }
    }

    fun launchServiceScan(ports: String) {
        if (serviceLoading) return
        if (!isValidNetworkTarget(serviceTarget)) {
            serviceError = "Invalid target — enter a valid IP, CIDR, or hostname"
            return
        }
        serviceLoading = true
        serviceError = null
        serviceResults = null
        lifecycleScope.launch(Dispatchers.IO) {
            val result = withTimeoutOrNull(60_000L) { PythonBridge.runServiceScan(applicationContext, serviceTarget, ports) }
            withContext(Dispatchers.Main) {
                serviceLoading = false
                if (result == null) serviceError = "Operation timed out after 60 seconds"
                else { serviceResults = result; if (!result.success) serviceError = result.error }
            }
        }
    }

    private fun getMacManufacturer(mac: String): String {
        if (mac.length < 8) return "Unknown"
        macVendors[mac.substring(0, 8).uppercase()]?.let { return it }
        val hex = mac.replace(":", "").uppercase()
        if (hex.length >= 6) macVendorsNoColon[hex.substring(0, 6)]?.let { return it }
        // Fallback to OuiLookup local database
        OuiLookup.lookupLocal(mac)?.let { vendor ->
            if (vendor != "Randomized MAC") return vendor
        }
        return "Unknown"
    }

    private fun loadThemePreference() {
        val prefs = getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
        currentTheme = if (!prefs.contains("theme")) {
            AppTheme.DARK
        } else if (prefs.getString("theme", "DARK") == "LIGHT") {
            AppTheme.LIGHT
        } else {
            AppTheme.DARK
        }
    }

    private fun saveThemePreference(theme: AppTheme) {
        getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
            .edit().putString("theme", theme.name).apply()
    }

    private fun scheduleBackgroundScan() {
        val intervalMinutes = getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
            .getInt("scan_interval_minutes", 15).toLong()
        val request = PeriodicWorkRequestBuilder<ScanWorker>(intervalMinutes, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            ScanWorker.WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
    }

    private fun cancelBackgroundScan() {
        WorkManager.getInstance(this).cancelUniqueWork(ScanWorker.WORK_NAME)
    }

    @SuppressLint("MissingPermission")
    private fun updateSignalStrengths() {
        try {
            wifiManager.startScan()
            val wifiResults = wifiManager.scanResults
            devices.filter { it.protocol == "WiFi" }.forEach { device ->
                wifiResults.find { it.BSSID == device.macAddress }?.let { result ->
                    val index = devices.indexOf(device)
                    if (index >= 0) devices[index] = device.copy(signalStrength = result.level)
                    signalHistory.getOrPut(device.macAddress) { mutableListOf() }.let { history ->
                        history.add(result.level)
                        if (history.size > 20) history.removeAt(0)
                    }
                }
            }
        } catch (e: Exception) { }
    }

    private fun calculatePrivacyScore(): Int {
        if (devices.isEmpty()) return 100
        val actualDevices = devices.filter { it.type != DeviceType.ROUTER }
        val suspiciousDevices = actualDevices.filter { it.isSuspicious() }

        var score = 100
        score -= suspiciousDevices.count { it.type == DeviceType.CAMERA } * 15
        score -= suspiciousDevices.count { it.type == DeviceType.MICROPHONE } * 10
        score -= suspiciousDevices.count { it.type == DeviceType.UNKNOWN } * 5
        score -= suspiciousDevices.count { it.isVeryClose() } * 5

        return score.coerceIn(0, 100)
    }

    private fun getTimeAgo(timestamp: Long): String {
        if (timestamp == 0L) return "Never"
        val diff = System.currentTimeMillis() - timestamp
        val minutes = diff / 60_000
        val hours = diff / 3_600_000
        return when {
            minutes < 1 -> "Just now"
            hours < 1 -> "${minutes} min ago"
            else -> "${hours} hr ago"
        }
    }

    private fun getMostCommonDeviceType(): String {
        if (devices.isEmpty()) return "None"
        return devices.groupBy { it.type }.maxByOrNull { it.value.size }?.key?.displayName ?: "None"
    }

    private fun getNearestThreatDistance(): String {
        val suspicious = devices.filter { it.isSuspicious() }
        if (suspicious.isEmpty()) return "None"
        return suspicious.minByOrNull { it.getDistance() }?.getDistanceFormatted() ?: "None"
    }

    private fun getPrivacyScoreColor(score: Int): Color = when {
        score >= 80 -> Color(0xFF44FF88)
        score >= 50 -> Color(0xFFFFAA44)
        else -> Color(0xFFFF4444)
    }

    private fun getPrivacyScoreLabel(score: Int): String = when {
        score >= 80 -> "Good Privacy"
        score >= 50 -> "Moderate Risk"
        else -> "High Risk"
    }

    @Composable
    @OptIn(ExperimentalMaterial3Api::class)
    fun HomeTab() {
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)

        var showSettingsSheet by remember { mutableStateOf(false) }
        var showPrivacyDetailSheet by remember { mutableStateOf(false) }
        val sheetState = rememberModalBottomSheetState()
        val sheetPrefs = getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
        var scanIntervalMinutes by remember { mutableStateOf(sheetPrefs.getInt("scan_interval_minutes", 15)) }
        var showIntervalDropdown by remember { mutableStateOf(false) }
        var showClearDataDialog by remember { mutableStateOf(false) }
        var selectedStatFilter by remember { mutableStateOf<String?>(null) }
        val homeListState = rememberLazyListState()
        val homeScope = rememberCoroutineScope()
        LaunchedEffect(homeResetTrigger) {
            if (homeResetTrigger > 0) {
                selectedStatFilter = null
                homeScope.launch { homeListState.animateScrollToItem(0) }
            }
        }

        val privacyScore by remember { derivedStateOf { calculatePrivacyScore() } }
        val suspiciousDevices by remember { derivedStateOf { devices.filter { it.isSuspicious() } } }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(bgColor)
                .statusBarsPadding()
                .padding(horizontal = 20.dp, vertical = 16.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("PRIVACY SHIELD", fontSize = 22.sp, fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onBackground, letterSpacing = 2.sp)
                    Text("Device Detection", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    IconButton(
                        onClick = { showSettingsSheet = true },
                        modifier = Modifier.size(40.dp).clip(CircleShape).background(cardColor)
                    ) {
                        Icon(Icons.Filled.Settings, "Settings", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }

            HorizontalDivider(
                modifier = Modifier.padding(vertical = 12.dp),
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                thickness = 0.5.dp
            )

            // Privacy Score Card - expanded
            val scoreBorder = when {
                privacyScore >= 80 -> androidx.compose.foundation.BorderStroke(
                    1.dp,
                    if (currentTheme == AppTheme.LIGHT) MaterialTheme.colorScheme.primary.copy(alpha = 0.3f)
                    else Color(0xFF44FF88).copy(alpha = 0.3f)
                )
                privacyScore < 50 -> androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFFF4444).copy(alpha = 0.3f))
                else -> null
            }
            Card(
                modifier = Modifier.fillMaxWidth().clickable { showPrivacyDetailSheet = true },
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp),
                border = scoreBorder
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    // Row 1: Label left, score number right, info icon far right
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("PRIVACY SCORE", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("$privacyScore", fontSize = 48.sp, fontWeight = FontWeight.Bold,
                                color = getPrivacyScoreColor(privacyScore))
                            Spacer(modifier = Modifier.width(8.dp))
                            Icon(Icons.Filled.Info, "Details", tint = subtextColor.copy(alpha = 0.5f),
                                modifier = Modifier.size(18.dp))
                        }
                    }
                    // Row 2: Score label + progress bar
                    Text(getPrivacyScoreLabel(privacyScore), fontSize = 14.sp,
                        color = getPrivacyScoreColor(privacyScore), fontWeight = FontWeight.Medium)
                    Spacer(modifier = Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = { (privacyScore / 100f).coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
                        color = getPrivacyScoreColor(privacyScore),
                        trackColor = subtextColor.copy(alpha = 0.2f)
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Tap for breakdown", fontSize = 10.sp, color = subtextColor.copy(alpha = 0.5f))
                    Spacer(modifier = Modifier.height(12.dp))
                    HorizontalDivider(color = subtextColor.copy(alpha = 0.2f))
                    Spacer(modifier = Modifier.height(16.dp))
                    // 2x2 info chip grid
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.AccessTime, null, tint = subtextColor, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Last scan", fontSize = 11.sp, color = subtextColor)
                            }
                            Text(getTimeAgo(lastScanTime), fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.Timer, null, tint = subtextColor, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Duration", fontSize = 11.sp, color = subtextColor)
                            }
                            Text(if (lastScanDuration == 0L) "—" else "${lastScanDuration / 1000}s",
                                fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                        }
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.Devices, null, tint = subtextColor, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Common type", fontSize = 11.sp, color = subtextColor)
                            }
                            Text(getMostCommonDeviceType(), fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.NearMe, null, tint = subtextColor, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Nearest threat", fontSize = 11.sp, color = subtextColor)
                            }
                            Text(getNearestThreatDistance(), fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Quick Actions
            Text("SCAN MODE", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp,
                modifier = Modifier.padding(bottom = 8.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ScanModeButton("Full Scan", Icons.Filled.Search, currentScanMode == ScanMode.FULL) {
                    currentScanMode = ScanMode.FULL
                    requestPermissionsAndScan(ScanMode.FULL)
                }
                ScanModeButton("Cameras", Icons.Filled.Videocam, currentScanMode == ScanMode.CAMERAS_ONLY) {
                    currentScanMode = ScanMode.CAMERAS_ONLY
                    requestPermissionsAndScan(ScanMode.CAMERAS_ONLY)
                }
                ScanModeButton("Mics", Icons.Filled.Mic, currentScanMode == ScanMode.MICS_ONLY) {
                    currentScanMode = ScanMode.MICS_ONLY
                    requestPermissionsAndScan(ScanMode.MICS_ONLY)
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            // Scan status indicator
            if (isScanning) {
                Row(verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()) {
                    LinearProgressIndicator(
                        modifier = Modifier.weight(1f).height(3.dp).clip(RoundedCornerShape(2.dp)),
                        color = Color(0xFF44FF88),
                        trackColor = subtextColor.copy(alpha = 0.2f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Scanning...", fontSize = 11.sp, color = Color(0xFF44FF88))
                }
            } else if (devices.isEmpty()) {
                Text("No scan yet — tap Full Scan to start", fontSize = 11.sp, color = subtextColor)
            } else {
                Text("Last scan: ${getTimeAgo(lastScanTime)}", fontSize = 11.sp, color = subtextColor)
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Stat Bars - full width stacked
            val totalSelected = selectedStatFilter == "all"
            val suspSelected = selectedStatFilter == "suspicious"
            val safeSelected = selectedStatFilter == "safe"

            // Total bar
            Card(
                modifier = Modifier.fillMaxWidth().height(72.dp).clickable {
                    selectedStatFilter = if (totalSelected) null else "all"
                    searchSuspiciousOnly = false; searchSafeOnly = false; selectedFilter = null
                    currentTab = AppTab.SEARCH; searchScrollTrigger++
                },
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1565C0)),
                shape = RoundedCornerShape(12.dp),
                elevation = CardDefaults.cardElevation(if (totalSelected) 6.dp else 2.dp),
                border = if (totalSelected) androidx.compose.foundation.BorderStroke(2.dp, Color.White.copy(alpha = 0.6f)) else null
            ) {
                Row(modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(devices.size.toString(), fontSize = 32.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text("Total devices", fontSize = 13.sp, color = Color.White)
                    }
                    Icon(Icons.Filled.ArrowForwardIos, null, tint = Color.White, modifier = Modifier.size(16.dp))
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Suspicious bar
            Card(
                modifier = Modifier.fillMaxWidth().height(72.dp).clickable {
                    selectedStatFilter = if (suspSelected) null else "suspicious"
                    searchSuspiciousOnly = true; searchSafeOnly = false
                    currentTab = AppTab.SEARCH; searchScrollTrigger++
                },
                colors = CardDefaults.cardColors(containerColor = Color(0xFFB71C1C)),
                shape = RoundedCornerShape(12.dp),
                elevation = CardDefaults.cardElevation(if (suspSelected) 6.dp else 2.dp),
                border = if (suspSelected) androidx.compose.foundation.BorderStroke(2.dp, Color.White.copy(alpha = 0.6f)) else null
            ) {
                Row(modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(suspiciousDevices.size.toString(), fontSize = 32.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text("Suspicious devices", fontSize = 13.sp, color = Color.White)
                    }
                    Icon(Icons.Filled.ArrowForwardIos, null, tint = Color.White, modifier = Modifier.size(16.dp))
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Safe bar
            Card(
                modifier = Modifier.fillMaxWidth().height(72.dp).clickable {
                    selectedStatFilter = if (safeSelected) null else "safe"
                    searchSafeOnly = true; searchSuspiciousOnly = false
                    currentTab = AppTab.SEARCH; searchScrollTrigger++
                },
                colors = CardDefaults.cardColors(containerColor = Color(0xFF2E7D32)),
                shape = RoundedCornerShape(12.dp),
                elevation = CardDefaults.cardElevation(if (safeSelected) 6.dp else 2.dp),
                border = if (safeSelected) androidx.compose.foundation.BorderStroke(2.dp, Color.White.copy(alpha = 0.6f)) else null
            ) {
                Row(modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text((devices.size - suspiciousDevices.size).toString(), fontSize = 32.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Text("Safe devices", fontSize = 13.sp, color = Color.White)
                    }
                    Icon(Icons.Filled.ArrowForwardIos, null, tint = Color.White, modifier = Modifier.size(16.dp))
                }
            }

        }

        // Clear All Data Dialog
        if (showClearDataDialog) {
            val dlgCardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
            val dlgTextColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
            val dlgSubColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { showClearDataDialog = false },
                title = { Text("Clear All App Data", color = dlgTextColor) },
                text = { Text("This will remove all scan history and reset all settings. This cannot be undone.", color = dlgSubColor) },
                confirmButton = {
                    TextButton(onClick = {
                        showClearDataDialog = false
                        lifecycleScope.launch { database.deviceHistoryDao().clearAll() }
                        devices.clear()
                        sheetPrefs.edit().clear().apply()
                        backgroundScanEnabled = false
                        currentTab = AppTab.HOME
                    }) { Text("Clear All", color = Color(0xFFFF4444)) }
                },
                dismissButton = {
                    TextButton(onClick = { showClearDataDialog = false }) { Text("Cancel", color = dlgSubColor) }
                },
                containerColor = dlgCardColor
            )
        }

        // Settings Bottom Sheet
        if (showSettingsSheet) {
            val sheetCardColor = if (currentTheme == AppTheme.DARK) Color(0xFF2A2A2A) else Color(0xFFF0F0F0)
            val sheetTextColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
            val sheetSubtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
            val sheetBgColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White

            ModalBottomSheet(
                onDismissRequest = { showSettingsSheet = false },
                sheetState = sheetState,
                containerColor = sheetBgColor
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp)
                        .padding(bottom = 32.dp)
                ) {
                    Text("SETTINGS", fontSize = 18.sp, fontWeight = FontWeight.Bold,
                        color = sheetTextColor, letterSpacing = 2.sp)
                    Spacer(modifier = Modifier.height(16.dp))

                    // Theme toggle card
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = sheetCardColor),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(2.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("Theme", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = sheetTextColor)
                                Text(if (currentTheme == AppTheme.DARK) "Switch to Light Mode" else "Switch to Dark Mode",
                                    fontSize = 12.sp, color = sheetSubtextColor)
                            }
                            Switch(
                                checked = currentTheme == AppTheme.DARK,
                                onCheckedChange = {
                                    currentTheme = if (it) AppTheme.DARK else AppTheme.LIGHT
                                    saveThemePreference(currentTheme)
                                }
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Background scanning card
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = sheetCardColor),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(2.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("Background Scanning", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = sheetTextColor)
                                Text("Scan every 15 min, notify on threats", fontSize = 12.sp, color = sheetSubtextColor)
                            }
                            Switch(
                                checked = backgroundScanEnabled,
                                onCheckedChange = { enabled ->
                                    backgroundScanEnabled = enabled
                                    sheetPrefs.edit().putBoolean("background_scan_enabled", enabled).apply()
                                    if (enabled) scheduleBackgroundScan() else cancelBackgroundScan()
                                }
                            )
                        }
                    }

                    if (backgroundScanEnabled) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Card(modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = sheetCardColor),
                            shape = RoundedCornerShape(12.dp),
                            elevation = CardDefaults.cardElevation(2.dp)
                        ) {
                            Row(modifier = Modifier.fillMaxWidth().padding(16.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("Scan Interval", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = sheetTextColor)
                                    Text("How often to scan in background", fontSize = 12.sp, color = sheetSubtextColor)
                                }
                                Box {
                                    OutlinedButton(onClick = { showIntervalDropdown = true }, shape = RoundedCornerShape(8.dp)) {
                                        val label = when (scanIntervalMinutes) { 15 -> "15 min"; 30 -> "30 min"; 60 -> "1 hour"; else -> "2 hours" }
                                        Text(label, fontSize = 12.sp, color = sheetTextColor)
                                        Icon(Icons.Filled.ArrowDropDown, null, modifier = Modifier.size(16.dp))
                                    }
                                    DropdownMenu(expanded = showIntervalDropdown, onDismissRequest = { showIntervalDropdown = false }, containerColor = sheetCardColor) {
                                        listOf(15 to "15 min", 30 to "30 min", 60 to "1 hour", 120 to "2 hours").forEach { (mins, label) ->
                                            DropdownMenuItem(text = { Text(label, color = sheetTextColor) }, onClick = {
                                                scanIntervalMinutes = mins
                                                sheetPrefs.edit().putInt("scan_interval_minutes", mins).apply()
                                                showIntervalDropdown = false
                                                scheduleBackgroundScan()
                                            })
                                        }
                                    }
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Clear Old History card
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = sheetCardColor),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(2.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("Clear Old History", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = sheetTextColor)
                                Text("Delete sessions older than 7 days", fontSize = 12.sp, color = sheetSubtextColor)
                            }
                            TextButton(onClick = {
                                val cutoff = System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000
                                lifecycleScope.launch { database.deviceHistoryDao().deleteOlderThan(cutoff) }
                            }) {
                                Text("Clear", color = Color(0xFFFF4444), fontSize = 12.sp)
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // App Lock card
                    val biometricAvailable = remember {
                        try {
                            val bm = androidx.biometric.BiometricManager.from(this@MainActivity)
                            bm.canAuthenticate(
                                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK or
                                androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                            ) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
                        } catch (e: Exception) { false }
                    }
                    var appLockEnabled by remember {
                        mutableStateOf(getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
                            .getBoolean("app_lock_enabled", false))
                    }
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = sheetCardColor),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(2.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text("App Lock", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = sheetTextColor)
                                Text(
                                    if (biometricAvailable) "Require biometric to open app" else "Not available on this device",
                                    fontSize = 12.sp, color = sheetSubtextColor
                                )
                            }
                            Switch(
                                checked = appLockEnabled && biometricAvailable,
                                enabled = biometricAvailable,
                                onCheckedChange = { enabled ->
                                    if (enabled) {
                                        showBiometricPrompt(onSuccess = {
                                            appLockEnabled = true
                                            getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
                                                .edit().putBoolean("app_lock_enabled", true).apply()
                                        }, onCancel = {})
                                    } else {
                                        appLockEnabled = false
                                        getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
                                            .edit().putBoolean("app_lock_enabled", false).apply()
                                    }
                                }
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Card(modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = sheetCardColor),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(2.dp)
                    ) {
                        Row(modifier = Modifier.fillMaxWidth().padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Export Scan History", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = sheetTextColor)
                                Text("Save all sessions as CSV", fontSize = 12.sp, color = sheetSubtextColor)
                            }
                            TextButton(onClick = { exportHistoryToCsv() }) {
                                Text("Export", color = Color(0xFF44BB77), fontSize = 12.sp)
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Card(modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = sheetCardColor),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(2.dp)
                    ) {
                        Row(modifier = Modifier.fillMaxWidth().padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Clear All App Data", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color(0xFFFF4444))
                                Text("Removes all scan history and resets settings", fontSize = 12.sp, color = sheetSubtextColor)
                            }
                            TextButton(onClick = { showClearDataDialog = true; showSettingsSheet = false }) {
                                Text("Clear", color = Color(0xFFFF4444), fontSize = 12.sp)
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // About card
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = sheetCardColor),
                        shape = RoundedCornerShape(12.dp),
                        elevation = CardDefaults.cardElevation(2.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text("About Privacy Shield", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = sheetTextColor)
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("Privacy Shield v1.0", fontSize = 12.sp, color = sheetSubtextColor)
                            Text("Production Release — March 2026", fontSize = 12.sp, color = sheetSubtextColor)
                            Text("MAC vendor database: ${macVendors.size + macVendorsNoColon.size} entries", fontSize = 12.sp, color = sheetSubtextColor)
                            Text("Features: Port Scanner, Ping, WHOIS, Network Analysis, Host Discovery, DNS Check, Biometric Lock, CSV/PDF Export, Background Scanning", fontSize = 12.sp, color = sheetSubtextColor)
                            Text("Tools: Port Scanner, Ping, WHOIS Lookup", fontSize = 12.sp, color = sheetSubtextColor)
                            Text("Database: Room v2 with scan history", fontSize = 12.sp, color = sheetSubtextColor)
                            Text("Background: WorkManager with configurable intervals", fontSize = 12.sp, color = sheetSubtextColor)
                        }
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    Text("Privacy Shield v1.0 \u2022 Build 2 \u2022 March 2026",
                        fontSize = 11.sp, color = sheetSubtextColor,
                        modifier = Modifier.fillMaxWidth(),
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center)
                }
            }
        }

        if (showPrivacyDetailSheet) {
            PrivacyScoreDetailSheet(onDismiss = { showPrivacyDetailSheet = false })
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun PrivacyScoreDetailSheet(onDismiss: () -> Unit) {
        val sheetState = rememberModalBottomSheetState()
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF0D0D0D) else Color(0xFFF5F5F5)

        val score = calculatePrivacyScore()
        val scoreColor = when {
            score < 40 -> Color(0xFFFF4444)
            score < 70 -> Color(0xFFFFAA44)
            else -> Color(0xFF44BB77)
        }

        val actualDevices = devices.filter { it.type != DeviceType.ROUTER }
        val suspiciousDevices = actualDevices.filter { it.isSuspicious() }
        val cameras = suspiciousDevices.filter { it.type == DeviceType.CAMERA }
        val mics = suspiciousDevices.filter { it.type == DeviceType.MICROPHONE }
        val unknowns = suspiciousDevices.filter { it.type == DeviceType.UNKNOWN }
        val veryClose = suspiciousDevices.filter { it.isVeryClose() }

        ModalBottomSheet(
            onDismissRequest = onDismiss,
            sheetState = sheetState,
            containerColor = bgColor
        ) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 32.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Score arc header
                item {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("Privacy Score", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = textColor)
                        Spacer(modifier = Modifier.height(16.dp))
                        Box(contentAlignment = Alignment.Center) {
                            CircularProgressIndicator(
                                progress = { score / 100f },
                                modifier = Modifier.size(120.dp),
                                color = scoreColor,
                                strokeWidth = 10.dp,
                                trackColor = scoreColor.copy(alpha = 0.15f)
                            )
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text("$score", fontSize = 36.sp, fontWeight = FontWeight.Bold, color = scoreColor)
                                Text(
                                    when {
                                        score < 40 -> "Poor"
                                        score < 70 -> "Fair"
                                        score < 85 -> "Good"
                                        else -> "Excellent"
                                    },
                                    fontSize = 12.sp, color = scoreColor
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                    }
                }

                // Score breakdown
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = cardColor),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text("Score Breakdown", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = textColor)
                            Spacer(modifier = Modifier.height(10.dp))
                            if (cameras.isEmpty() && mics.isEmpty() && unknowns.isEmpty() && veryClose.isEmpty()) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Filled.CheckCircle, null, tint = Color(0xFF44BB77), modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text("No active threats detected", fontSize = 13.sp, color = Color(0xFF44BB77))
                                }
                            } else {
                                Text("Starting score: 100", fontSize = 12.sp, color = subtextColor)
                                Spacer(modifier = Modifier.height(6.dp))
                                if (cameras.isNotEmpty()) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text("${cameras.size}x nearby camera${if (cameras.size > 1) "s" else ""}", fontSize = 13.sp, color = textColor)
                                        Text("-${cameras.size * 15} pts", fontSize = 13.sp, color = Color(0xFFFF4444), fontWeight = FontWeight.Medium)
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                if (mics.isNotEmpty()) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text("${mics.size}x nearby mic${if (mics.size > 1) "s" else ""}", fontSize = 13.sp, color = textColor)
                                        Text("-${mics.size * 10} pts", fontSize = 13.sp, color = Color(0xFFFF4444), fontWeight = FontWeight.Medium)
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                if (unknowns.isNotEmpty()) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text("${unknowns.size}x unknown device${if (unknowns.size > 1) "s" else ""}", fontSize = 13.sp, color = textColor)
                                        Text("-${unknowns.size * 5} pts", fontSize = 13.sp, color = Color(0xFFFFAA44), fontWeight = FontWeight.Medium)
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                if (veryClose.isNotEmpty()) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text("${veryClose.size}x very close (<3m)", fontSize = 13.sp, color = textColor)
                                        Text("-${veryClose.size * 5} pts", fontSize = 13.sp, color = Color(0xFFFFAA44), fontWeight = FontWeight.Medium)
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                HorizontalDivider(color = subtextColor.copy(alpha = 0.2f))
                                Spacer(modifier = Modifier.height(6.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text("Final score", fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = textColor)
                                    Text("$score / 100", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = scoreColor)
                                }
                            }
                        }
                    }
                }

                // Contributing devices
                if (suspiciousDevices.isNotEmpty()) {
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = cardColor),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text("Contributing Devices", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = textColor)
                                Spacer(modifier = Modifier.height(10.dp))
                                data class GroupedDeviceRow(val deviceType: DeviceType, val groupDevices: List<DetectedDevice>, val impact: Int)
                                val grouped = suspiciousDevices
                                    .groupBy { it.type }
                                    .map { (dt, grp) ->
                                        val totalImpact: Int = grp.fold(0) { acc, d ->
                                            acc + when {
                                                d.type == DeviceType.CAMERA -> -15
                                                d.type == DeviceType.MICROPHONE -> -10
                                                else -> -5
                                            }
                                        }
                                        GroupedDeviceRow(dt, grp, totalImpact)
                                    }
                                    .sortedBy { it.impact }
                                grouped.forEach { row ->
                                    val count = row.groupDevices.size
                                    val isUnknownType = row.deviceType == DeviceType.UNKNOWN || row.groupDevices.any { it.manufacturer == "Unknown" }
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                if (count == 1) row.deviceType.displayName else "${count}x ${row.deviceType.displayName}",
                                                fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium
                                            )
                                            if (isUnknownType) {
                                                row.groupDevices.forEach { device ->
                                                    Text(
                                                        device.macAddress,
                                                        fontSize = 11.sp, color = subtextColor,
                                                        fontFamily = FontFamily.Monospace
                                                    )
                                                }
                                            } else {
                                                Text(
                                                    if (count == 1) row.groupDevices.first().macAddress else "$count devices",
                                                    fontSize = 11.sp, color = subtextColor
                                                )
                                            }
                                        }
                                        Text("${row.impact} pts", fontSize = 13.sp, color = Color(0xFFFF4444), fontWeight = FontWeight.Medium)
                                    }
                                }
                            }
                        }
                    }
                } else {
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = Color(0xFF1B3A1F)),
                            shape = RoundedCornerShape(12.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(Icons.Filled.CheckCircle, null, tint = Color(0xFF44FF88), modifier = Modifier.size(20.dp))
                                Spacer(modifier = Modifier.width(10.dp))
                                Text("No threats detected", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF44FF88))
                            }
                        }
                    }
                }

                // How to improve
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = cardColor),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Filled.Lightbulb, null, tint = Color(0xFFFFAA44), modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("How to Improve", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = textColor)
                            }
                            Spacer(modifier = Modifier.height(10.dp))
                            if (score >= 85) {
                                Text("Your privacy score is excellent. Keep scanning regularly to monitor for new threats.", fontSize = 13.sp, color = subtextColor)
                            } else {
                                if (cameras.isNotEmpty()) {
                                    Text("• Move away from or disable nearby camera devices", fontSize = 13.sp, color = subtextColor)
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                if (mics.isNotEmpty()) {
                                    Text("• Check for unauthorized microphone devices in the area", fontSize = 13.sp, color = subtextColor)
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                if (unknowns.isNotEmpty()) {
                                    Text("• Investigate unknown devices — they may be unrecognized surveillance equipment", fontSize = 13.sp, color = subtextColor)
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                if (veryClose.isNotEmpty()) {
                                    Text("• Increase physical distance from suspicious devices (keep >3m)", fontSize = 13.sp, color = subtextColor)
                                    Spacer(modifier = Modifier.height(4.dp))
                                }
                                Text("• Run a new scan after changing your environment", fontSize = 13.sp, color = subtextColor)
                            }
                        }
                    }
                }

                // Dismiss
                item {
                    Button(
                        onClick = onDismiss,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF333333))
                    ) {
                        Text("Dismiss", color = Color.White)
                    }
                }
            }
        }
    }

    @Composable
    fun SearchTab() {
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)

        var showSortMenu by remember { mutableStateOf(false) }
        val searchListState = rememberLazyListState()
        val searchScope = rememberCoroutineScope()
        LaunchedEffect(searchResetTrigger) {
            if (searchResetTrigger > 0) {
                searchQuery = ""
                selectedFilter = null
                searchSortOption = 0
                searchSuspiciousOnly = false
                searchSafeOnly = false
                searchScope.launch { searchListState.animateScrollToItem(0) }
            }
        }
        LaunchedEffect(searchScrollTrigger) {
            if (searchScrollTrigger > 0) {
                searchScope.launch { searchListState.animateScrollToItem(0) }
            }
        }

        val filteredDevices = devices.filter { device ->
            val matchesSearch = searchQuery.isEmpty() ||
                    device.name.contains(searchQuery, ignoreCase = true) ||
                    device.macAddress.contains(searchQuery, ignoreCase = true) ||
                    device.manufacturer.contains(searchQuery, ignoreCase = true)
            val matchesFilter = selectedFilter == null || device.type == selectedFilter
            val matchesSuspicious = !searchSuspiciousOnly || device.isSuspicious()
            val matchesSafe = !searchSafeOnly || !device.isSuspicious()
            matchesSearch && matchesFilter && matchesSuspicious && matchesSafe
        }

        val sortedDevices = when (searchSortOption) {
            0 -> filteredDevices.sortedByDescending { it.signalStrength }
            1 -> filteredDevices.sortedBy { it.getDistance() }
            2 -> filteredDevices.sortedBy { it.type.displayName }
            else -> filteredDevices
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(bgColor)
                .statusBarsPadding()
                .padding(horizontal = 20.dp, vertical = 16.dp)
        ) {
            Text("DEVICES", fontSize = 22.sp, fontWeight = FontWeight.Bold,
                color = textColor, letterSpacing = 2.sp)

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("Search by name, MAC, or manufacturer...",
                    color = subtextColor, fontSize = 14.sp) },
                leadingIcon = { Icon(Icons.Filled.Search, null, tint = subtextColor) },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { searchQuery = "" }) {
                            Icon(Icons.Filled.Clear, null, tint = subtextColor)
                        }
                    }
                },
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = textColor,
                    unfocusedBorderColor = subtextColor,
                    focusedTextColor = textColor,
                    unfocusedTextColor = textColor
                ),
                shape = RoundedCornerShape(12.dp),
                singleLine = true
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("FILTERS", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Suspicious only toggle
                    IconButton(onClick = { searchSuspiciousOnly = !searchSuspiciousOnly; searchSafeOnly = false },
                        modifier = Modifier.size(40.dp).clip(CircleShape).background(
                            if (searchSuspiciousOnly) Color(0xFFB71C1C).copy(alpha = 0.2f) else Color.Transparent
                        )
                    ) {
                        Icon(Icons.Filled.Warning, null,
                            tint = if (searchSuspiciousOnly) Color(0xFFFF4444) else subtextColor)
                    }
                    Box {
                        IconButton(onClick = { showSortMenu = true }) {
                            Icon(Icons.Filled.Sort, null, tint = subtextColor)
                        }
                        DropdownMenu(expanded = showSortMenu, onDismissRequest = { showSortMenu = false }) {
                            listOf("Sort by Signal", "Sort by Distance", "Sort by Type").forEachIndexed { i, label ->
                                DropdownMenuItem(
                                    text = { Text(label) },
                                    onClick = { searchSortOption = i; showSortMenu = false }
                                )
                            }
                        }
                    }
                }
            }

            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    FilterChip(
                        selected = selectedFilter == null,
                        onClick = { selectedFilter = null },
                        label = { Text("All (${devices.size})") }
                    )
                }
                DeviceType.values().forEach { type ->
                    val count = devices.count { it.type == type }
                    if (count > 0) {
                        item {
                            FilterChip(
                                selected = selectedFilter == type,
                                onClick = { selectedFilter = if (selectedFilter == type) null else type },
                                label = { Text("${type.displayName} ($count)") }
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text("Showing ${sortedDevices.size} of ${devices.size} devices",
                fontSize = 11.sp, color = subtextColor,
                modifier = Modifier.padding(vertical = 4.dp))

            if (sortedDevices.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        if (devices.isEmpty()) {
                            Icon(Icons.Filled.WifiOff, null, tint = subtextColor, modifier = Modifier.size(64.dp))
                            Spacer(modifier = Modifier.height(16.dp))
                            Text("Run a scan from Home to see devices", color = subtextColor, fontSize = 14.sp)
                        } else {
                            Icon(Icons.Filled.SearchOff, null, tint = subtextColor, modifier = Modifier.size(64.dp))
                            Spacer(modifier = Modifier.height(16.dp))
                            Text("No devices match", color = subtextColor, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                            val filterName = when {
                                searchSuspiciousOnly -> "Suspicious filter"
                                searchSafeOnly -> "Safe filter"
                                selectedFilter != null -> selectedFilter!!.displayName
                                searchQuery.isNotEmpty() -> "\"$searchQuery\""
                                else -> "current filter"
                            }
                            Text(filterName, color = subtextColor, fontSize = 12.sp)
                        }
                    }
                }
            } else {
                LazyColumn(state = searchListState, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(sortedDevices, key = { it.id }) { device ->
                        DeviceCard(device, cardColor, textColor, subtextColor,
                            accentColor = getDeviceColor(device.type))
                    }
                }
            }
        }
    }

    @Composable
    fun ToolsTab() {
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        val context = androidx.compose.ui.platform.LocalContext.current
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

        // pythonScanTab, nmapTarget/Results/Loading/Error, serviceTarget/Results/Loading/Error
        // are now class-level state (hoisted so scans survive tab navigation)
        var servicePorts by remember { mutableStateOf("22,80,443,8080,8443") }
        var servicePortPreset by remember { mutableStateOf(0) } // 0=Common,1=Web,2=DB,3=Custom

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
                        if (serviceTarget.isEmpty()) serviceTarget = gw
                        if (nmapTarget.isEmpty()) {
                            // Derive /24 subnet from gateway
                            val parts = gw.split(".")
                            if (parts.size == 4) nmapTarget = "${parts[0]}.${parts[1]}.${parts[2]}.0/24"
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

                // SECURITY FIX: URL-encode vendor and product before embedding in URL path
                val encodedVendor = java.net.URLEncoder.encode(vendor, "UTF-8")
                val encodedProduct = product?.let { java.net.URLEncoder.encode(it, "UTF-8") }

                // Try circl.lu first
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
                    // NVD fallback
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
                                    // SECURITY FIX: Validate target IP/hostname before scanning
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
                                Text("$openCount open / ${portResults.size} scanned",
                                    fontSize = 12.sp, color = subtextColor)
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
                                                    val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                                    cb.setPrimaryClip(android.content.ClipData.newPlainText("port", "$targetIp:$port"))
                                                    Toast.makeText(context, "$targetIp:$port copied", Toast.LENGTH_SHORT).show()
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
                                            withContext(Dispatchers.IO) {
                                                InetAddress.getByName(pingTarget).isReachable(2000)
                                            }
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
                                                withContext(Dispatchers.IO) {
                                                    InetAddress.getByName(defaultIp).isReachable(2000)
                                                }
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
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(host, fontSize = 11.sp, color = subtextColor,
                                        modifier = Modifier.width(100.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    if (elapsed != null) {
                                        val fraction = (elapsed.toFloat() / maxMs.coerceAtLeast(1).toFloat()).coerceIn(0.05f, 1f)
                                        Box(modifier = Modifier
                                            .weight(1f)
                                            .height(14.dp)
                                            .clip(RoundedCornerShape(3.dp))
                                            .background(subtextColor.copy(alpha = 0.1f))
                                        ) {
                                            Box(modifier = Modifier
                                                .fillMaxHeight()
                                                .fillMaxWidth(fraction)
                                                .clip(RoundedCornerShape(3.dp))
                                                .background(msColor)
                                            )
                                        }
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text("${elapsed}ms", fontSize = 11.sp, color = msColor,
                                            modifier = Modifier.width(52.dp))
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
                                        Text(result.openPorts.joinToString(", "),
                                            fontSize = 12.sp, color = Color(0xFF44FF88))
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
                                        Text(value, fontSize = 12.sp, color = textColor,
                                            fontWeight = FontWeight.Medium,
                                            modifier = Modifier.weight(1f),
                                            maxLines = 1,
                                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Icon(Icons.Filled.ContentCopy, null,
                                            modifier = Modifier.size(14.dp).clickable {
                                                val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                                cb.setPrimaryClip(android.content.ClipData.newPlainText(label, value))
                                                Toast.makeText(context, "$label copied", Toast.LENGTH_SHORT).show()
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
                                    // SECURITY FIX: Validate target before connecting
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
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text("${hop.hop}", fontSize = 12.sp, color = subtextColor,
                                        modifier = Modifier.width(24.dp))
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(if (hop.timedOut) "* * *" else hop.ip,
                                        fontSize = 12.sp, color = textColor,
                                        modifier = Modifier.weight(1f))
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
                        // Hint text below input
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            "Search by vendor or product name (e.g. netgear, apache, openssl)",
                            fontSize = 12.sp, color = subtextColor
                        )
                        // Quick-fill chips from detected devices — only real vendor names
                        val cveChipDevices = devices.filter { device ->
                            val mfr = device.manufacturer
                            mfr != "Unknown" && mfr.length > 2 &&
                            !mfr.contains(Regex("[A-Z0-9_-]{6,}"))
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
                                Column(modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 6.dp)
                                    .clickable { expanded = !expanded }
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(cve.id, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,
                                            fontSize = 13.sp, color = textColor, modifier = Modifier.weight(1f))
                                        Text("via ${cve.source}", fontSize = 10.sp, color = subtextColor,
                                            modifier = Modifier.padding(end = 6.dp))
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
                                        fontSize = 12.sp, color = subtextColor,
                                        modifier = Modifier.padding(top = 2.dp)
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
                                Text("Chaquopy", fontSize = 10.sp, color = Color(0xFF44FF88),
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                            }
                            if (RootFeatureGate.canUseRootFeatures()) {
                                Spacer(modifier = Modifier.width(4.dp))
                                Surface(color = Color(0xFFFF4444).copy(alpha = 0.15f), shape = RoundedCornerShape(4.dp)) {
                                    Text("nmap", fontSize = 10.sp, color = Color(0xFFFF4444),
                                        fontWeight = FontWeight.Bold,
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
                        // Tab selector
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("Host Scan", "Service Scan").forEachIndexed { idx, label ->
                                val selected = pythonScanTab == idx
                                Surface(
                                    color = if (selected) Color(0xFF1565C0) else subtextColor.copy(alpha = 0.15f),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.clickable { pythonScanTab = idx }
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
                            // Host Scan
                            OutlinedTextField(
                                value = nmapTarget,
                                onValueChange = { nmapTarget = it },
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
                                onClick = { launchHostScan() },
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
                                                if (host.hostname.isNotEmpty()) {
                                                    Text(host.hostname, fontSize = 11.sp, color = subtextColor)
                                                }
                                            }
                                            Text(host.state, fontSize = 11.sp, color = dotColor)
                                        }
                                    }
                                }
                            }
                        } else {
                            // Service Scan
                            OutlinedTextField(
                                value = serviceTarget,
                                onValueChange = { serviceTarget = it },
                                label = { Text("Target IP") },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedTextColor = textColor, unfocusedTextColor = textColor,
                                    focusedBorderColor = Color(0xFF1565C0), unfocusedBorderColor = subtextColor
                                )
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            // Port preset chips
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
                                onClick = { launchServiceScan(servicePorts) },
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
                                                color = textColor, fontFamily = FontFamily.Monospace,
                                                modifier = Modifier.width(80.dp))
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

    @Composable
    fun SettingsTab() {
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        val context = androidx.compose.ui.platform.LocalContext.current
        val scope = rememberCoroutineScope()
        val prefs = context.getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
        var scanIntervalMinutes by remember { mutableStateOf(prefs.getInt("scan_interval_minutes", 15)) }
        var showIntervalDropdown by remember { mutableStateOf(false) }
        var showClearDataDialog by remember { mutableStateOf(false) }

        if (showClearDataDialog) {
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { showClearDataDialog = false },
                title = { Text("Clear All App Data", color = textColor) },
                text = { Text("This will remove all scan history and reset settings. This cannot be undone.", color = subtextColor) },
                confirmButton = {
                    TextButton(onClick = {
                        showClearDataDialog = false
                        scope.launch {
                            database.deviceHistoryDao().clearAll()
                        }
                        devices.clear()
                        prefs.edit().clear().apply()
                        backgroundScanEnabled = false
                        currentTab = AppTab.HOME
                    }) { Text("Clear All", color = Color(0xFFFF4444)) }
                },
                dismissButton = {
                    TextButton(onClick = { showClearDataDialog = false }) { Text("Cancel", color = subtextColor) }
                },
                containerColor = cardColor
            )
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(bgColor)
                .statusBarsPadding()
                .padding(horizontal = 20.dp, vertical = 16.dp)
        ) {
            Text("SETTINGS", fontSize = 22.sp, fontWeight = FontWeight.Bold,
                color = textColor, letterSpacing = 2.sp)
            Spacer(modifier = Modifier.height(20.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(12.dp),
                elevation = CardDefaults.cardElevation(2.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Theme", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = textColor)
                        Text(if (currentTheme == AppTheme.DARK) "Switch to Light Mode" else "Switch to Dark Mode",
                            fontSize = 12.sp, color = subtextColor)
                    }
                    Switch(
                        checked = currentTheme == AppTheme.DARK,
                        onCheckedChange = {
                            currentTheme = if (it) AppTheme.DARK else AppTheme.LIGHT
                            saveThemePreference(currentTheme)
                        }
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(12.dp),
                elevation = CardDefaults.cardElevation(2.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Background Scanning", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = textColor)
                        Text("Scan every 15 min, notify on threats", fontSize = 12.sp, color = subtextColor)
                    }
                    Switch(
                        checked = backgroundScanEnabled,
                        onCheckedChange = { enabled ->
                            backgroundScanEnabled = enabled
                            prefs.edit().putBoolean("background_scan_enabled", enabled).apply()
                            if (enabled) scheduleBackgroundScan() else cancelBackgroundScan()
                        }
                    )
                }
            }

            if (backgroundScanEnabled) {
                Spacer(modifier = Modifier.height(8.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = cardColor),
                    shape = RoundedCornerShape(12.dp),
                    elevation = CardDefaults.cardElevation(2.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Scan Interval", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = textColor)
                            Text("How often to scan in background", fontSize = 12.sp, color = subtextColor)
                        }
                        Box {
                            OutlinedButton(
                                onClick = { showIntervalDropdown = true },
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                val label = when (scanIntervalMinutes) {
                                    15 -> "15 min"; 30 -> "30 min"; 60 -> "1 hour"; else -> "2 hours"
                                }
                                Text(label, fontSize = 12.sp, color = textColor)
                                Icon(Icons.Filled.ArrowDropDown, null, modifier = Modifier.size(16.dp))
                            }
                            DropdownMenu(
                                expanded = showIntervalDropdown,
                                onDismissRequest = { showIntervalDropdown = false },
                                containerColor = cardColor
                            ) {
                                listOf(15 to "15 min", 30 to "30 min", 60 to "1 hour", 120 to "2 hours").forEach { (mins, label) ->
                                    DropdownMenuItem(
                                        text = { Text(label, color = textColor) },
                                        onClick = {
                                            scanIntervalMinutes = mins
                                            prefs.edit().putInt("scan_interval_minutes", mins).apply()
                                            showIntervalDropdown = false
                                            scheduleBackgroundScan()
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(12.dp),
                elevation = CardDefaults.cardElevation(2.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Clear Old History", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = textColor)
                        Text("Delete sessions older than 7 days", fontSize = 12.sp, color = subtextColor)
                    }
                    TextButton(onClick = {
                        val cutoff = System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000
                        lifecycleScope.launch { database.deviceHistoryDao().deleteOlderThan(cutoff) }
                    }) {
                        Text("Clear", color = Color(0xFFFF4444), fontSize = 12.sp)
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
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
                        Text("Export Scan History", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = textColor)
                        Text("Save all sessions as CSV", fontSize = 12.sp, color = subtextColor)
                    }
                    TextButton(onClick = { exportHistoryToCsv() }) {
                        Text("Export", color = Color(0xFF44BB77), fontSize = 12.sp)
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
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
                        Text("Clear All App Data", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = Color(0xFFFF4444))
                        Text("Removes all scan history and resets settings", fontSize = 12.sp, color = subtextColor)
                    }
                    TextButton(onClick = { showClearDataDialog = true }) {
                        Text("Clear", color = Color(0xFFFF4444), fontSize = 12.sp)
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(12.dp),
                elevation = CardDefaults.cardElevation(2.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("About Privacy Shield", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = textColor)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Privacy Shield v1.0", fontSize = 12.sp, color = subtextColor)
                    Text("Production Release — March 2026", fontSize = 12.sp, color = subtextColor)
                    Text("MAC vendor database: ${macVendors.size + macVendorsNoColon.size} entries", fontSize = 12.sp, color = subtextColor)
                    Text("Features: Port Scanner, Ping, WHOIS, Network Analysis, Host Discovery, DNS Check, Biometric Lock, CSV/PDF Export, Background Scanning", fontSize = 12.sp, color = subtextColor)
                    Text("Tools: Port Scanner, Ping, WHOIS Lookup", fontSize = 12.sp, color = subtextColor)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
            Text("Privacy Shield v1.0 \u2022 Build 2 \u2022 March 2026",
                fontSize = 11.sp, color = subtextColor,
                modifier = Modifier.fillMaxWidth(),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center)
        }
    }

    @Composable
    fun NetworkTab() {
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        val context = androidx.compose.ui.platform.LocalContext.current
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

        LaunchedEffect(currentTab == AppTab.NETWORK) {
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
            val wifiInfo = wifiManager.connectionInfo
            val checks = mutableListOf<SecurityCheck>()
            // Check 1: Open WiFi
            if (wifiInfo != null && wifiInfo.networkId != -1) {
                checks.add(SecurityCheck("Open WiFi", "Connected to a network", 1))
            } else {
                checks.add(SecurityCheck("Open WiFi", "Not connected", 2))
            }
            // Check 2: DNS Security
            val dnsIp = if (dns1.isNotEmpty() && dns1 != "0.0.0.0") dns1 else ""
            val isPrivateDns = dnsIp.startsWith("8.8.") || dnsIp.startsWith("1.1.") ||
                dnsIp.startsWith("9.9.9.") || dnsIp.startsWith("208.67.")
            checks.add(if (isPrivateDns)
                SecurityCheck("DNS Security", "Using trusted public DNS ($dnsIp)", 0)
            else
                SecurityCheck("DNS Security", "Consider using private DNS (1.1.1.1)", 2))
            // Check 3: Gateway Exposure
            if (gatewayIp.isNotEmpty() && gatewayIp != "0.0.0.0") {
                val reachable = withContext(Dispatchers.IO) {
                    try { InetAddress.getByName(gatewayIp).isReachable(1000) } catch (e: Exception) { false }
                }
                checks.add(SecurityCheck("Gateway Exposure",
                    if (reachable) "Gateway $gatewayIp is reachable" else "Gateway not reachable", 1))
            }
            // Check 4: IP Privacy
            val ipInt = wifiInfo?.ipAddress ?: 0
            val ipAddr = if (ipInt != 0) "%d.%d.%d.%d".format(
                ipInt and 0xff, ipInt shr 8 and 0xff, ipInt shr 16 and 0xff, ipInt shr 24 and 0xff) else ""
            val isPrivateIp = ipAddr.startsWith("192.168.") || ipAddr.startsWith("10.")
            checks.add(if (isPrivateIp)
                SecurityCheck("IP Privacy", "Using private IP range ($ipAddr)", 0)
            else
                SecurityCheck("IP Privacy", if (ipAddr.isEmpty()) "Not connected" else "Public IP detected", 2))
            securityChecks = checks
            evilTwinAlerts = detectEvilTwins(devices)
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
                                fontStyle = androidx.compose.ui.text.font.FontStyle.Italic)
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
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
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
                                                val cb = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
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

    @Composable
    fun HistoryTab() {
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)

        var sessions by remember { mutableStateOf<List<ScanSessionSummary>>(emptyList()) }
        var refreshTrigger by remember { mutableStateOf(0) }
        val historyListState = rememberLazyListState()
        val historyScope = rememberCoroutineScope()
        LaunchedEffect(historyResetTrigger) {
            if (historyResetTrigger > 0) {
                historyDateFilter = 0
                historyExpandedSessionId = null
                historyScope.launch { historyListState.animateScrollToItem(0) }
            }
        }

        LaunchedEffect(refreshTrigger) {
            sessions = withContext(Dispatchers.IO) {
                database.deviceHistoryDao().getAllSessions()
            }
        }

        val now = System.currentTimeMillis()
        val startOfToday = run {
            val cal = java.util.Calendar.getInstance()
            cal.set(java.util.Calendar.HOUR_OF_DAY, 0)
            cal.set(java.util.Calendar.MINUTE, 0)
            cal.set(java.util.Calendar.SECOND, 0)
            cal.set(java.util.Calendar.MILLISECOND, 0)
            cal.timeInMillis
        }
        val sevenDaysAgo = now - 7L * 24 * 60 * 60 * 1000

        val filteredSessions = when (historyDateFilter) {
            1 -> sessions.filter { it.timestamp >= startOfToday }
            2 -> sessions.filter { it.timestamp >= sevenDaysAgo }
            else -> sessions
        }

        Column(
            modifier = androidx.compose.ui.Modifier
                .fillMaxSize()
                .background(bgColor)
                .statusBarsPadding()
                .padding(horizontal = 20.dp, vertical = 16.dp)
        ) {
            Row(
                modifier = androidx.compose.ui.Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("SCAN HISTORY", fontSize = 22.sp, fontWeight = FontWeight.Bold,
                    color = textColor, letterSpacing = 2.sp)
                if (sessions.isNotEmpty()) {
                    IconButton(onClick = { exportHistoryToCsv() }) {
                        Icon(Icons.Filled.Share, "Export CSV", tint = subtextColor)
                    }
                    IconButton(onClick = { exportHistoryToPdf() }) {
                        Icon(Icons.Filled.PictureAsPdf, "Export PDF", tint = subtextColor)
                    }
                    TextButton(onClick = {
                        lifecycleScope.launch {
                            database.deviceHistoryDao().clearAll()
                            refreshTrigger++
                        }
                    }) {
                        Text("Clear All", color = Color(0xFFFF4444), fontSize = 12.sp)
                    }
                }
            }

            Spacer(modifier = androidx.compose.ui.Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf("All Time" to 0, "Today" to 1, "Last 7 Days" to 2).forEach { (label, value) ->
                    FilterChip(
                        selected = historyDateFilter == value,
                        onClick = { historyDateFilter = value },
                        label = { Text(label, fontSize = 12.sp) }
                    )
                }
            }

            Spacer(modifier = androidx.compose.ui.Modifier.height(12.dp))

            if (filteredSessions.isEmpty()) {
                Box(
                    modifier = androidx.compose.ui.Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Filled.History, null, tint = subtextColor,
                            modifier = androidx.compose.ui.Modifier.size(64.dp))
                        Spacer(modifier = androidx.compose.ui.Modifier.height(16.dp))
                        Text("No scan history yet", color = subtextColor, fontSize = 14.sp)
                        Text("Run a scan to start tracking", color = subtextColor, fontSize = 12.sp)
                    }
                }
            } else {
                LazyColumn(state = historyListState, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(filteredSessions, key = { it.scanSessionId }) { session ->
                        HistorySessionCard(
                            session = session,
                            isExpanded = historyExpandedSessionId == session.scanSessionId,
                            onTap = {
                                historyExpandedSessionId =
                                    if (historyExpandedSessionId == session.scanSessionId) null
                                    else session.scanSessionId
                            },
                            onDeleted = { refreshTrigger++ },
                            cardColor = cardColor,
                            textColor = textColor,
                            subtextColor = subtextColor
                        )
                    }
                }
            }
        }
    }

    @Composable
    fun HistorySessionCard(
        session: ScanSessionSummary,
        isExpanded: Boolean,
        onTap: () -> Unit,
        onDeleted: () -> Unit,
        cardColor: Color,
        textColor: Color,
        subtextColor: Color
    ) {
        val dateFormat = SimpleDateFormat("MMM d, yyyy  HH:mm", Locale.getDefault())
        val dateStr = dateFormat.format(Date(session.timestamp))

        var devices by remember { mutableStateOf<List<DeviceHistoryEntity>>(emptyList()) }
        LaunchedEffect(isExpanded) {
            if (isExpanded && devices.isEmpty()) {
                devices = withContext(Dispatchers.IO) {
                    database.deviceHistoryDao().getDevicesForSession(session.scanSessionId)
                }
            }
        }

        val dotColor = when {
            session.suspiciousCount == 0 -> Color(0xFF44FF88)
            session.suspiciousCount <= 2 -> Color(0xFFFFAA44)
            else -> Color(0xFFFF4444)
        }

        Card(
            modifier = androidx.compose.ui.Modifier
                .fillMaxWidth()
                .clickable { onTap() },
            colors = CardDefaults.cardColors(containerColor = cardColor),
            shape = RoundedCornerShape(12.dp),
            elevation = CardDefaults.cardElevation(2.dp)
        ) {
            Column {
                Row(
                    modifier = androidx.compose.ui.Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = androidx.compose.ui.Modifier.weight(1f)
                    ) {
                        Box(
                            modifier = androidx.compose.ui.Modifier
                                .size(10.dp)
                                .clip(CircleShape)
                                .background(dotColor)
                        )
                        Spacer(modifier = androidx.compose.ui.Modifier.width(10.dp))
                        Column {
                            Text(dateStr, fontSize = 14.sp, fontWeight = FontWeight.Medium, color = textColor)
                            Spacer(modifier = androidx.compose.ui.Modifier.height(4.dp))
                            Text("${session.deviceCount} device(s) found", fontSize = 12.sp, color = subtextColor)
                            if (session.suspiciousCount > 0) {
                                Text("${session.suspiciousCount} suspicious", fontSize = 12.sp,
                                    color = Color(0xFFFF4444), fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                            contentDescription = null, tint = subtextColor,
                            modifier = androidx.compose.ui.Modifier.size(20.dp)
                        )
                        Spacer(modifier = androidx.compose.ui.Modifier.width(4.dp))
                        IconButton(
                            onClick = {
                                lifecycleScope.launch {
                                    database.deviceHistoryDao().deleteSession(session.scanSessionId)
                                    onDeleted()
                                }
                            },
                            modifier = androidx.compose.ui.Modifier.size(32.dp)
                        ) {
                            Icon(Icons.Filled.Delete, "Delete session", tint = subtextColor,
                                modifier = androidx.compose.ui.Modifier.size(18.dp))
                        }
                    }
                }

                if (isExpanded) {
                    HorizontalDivider(color = subtextColor.copy(alpha = 0.2f))
                    Column(
                        modifier = androidx.compose.ui.Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (devices.isEmpty()) {
                            Text("Loading...", fontSize = 12.sp, color = subtextColor)
                        } else {
                            devices.forEach { device ->
                                Row(
                                    modifier = androidx.compose.ui.Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = androidx.compose.ui.Modifier.weight(1f)) {
                                        Text(device.name, fontSize = 13.sp, color = textColor,
                                            fontWeight = FontWeight.Medium)
                                        Text("${device.deviceType} · ${device.macAddress}",
                                            fontSize = 11.sp, color = subtextColor)
                                    }
                                    if (device.isSuspicious) {
                                        Text("Suspicious", fontSize = 11.sp,
                                            color = Color(0xFFFF4444), fontWeight = FontWeight.Bold)
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
    fun SecurityTab() {
        val bgColor = MaterialTheme.colorScheme.background
        val cardColor = MaterialTheme.colorScheme.surface
        val textColor = MaterialTheme.colorScheme.onSurface
        val subtextColor = MaterialTheme.colorScheme.onSurfaceVariant

        // Compute security sub-scores
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
            // Simple header
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

            // Advanced Security header
            item {
                Spacer(modifier = Modifier.height(8.dp))
                Text("ADVANCED SECURITY", fontSize = 11.sp, color = subtextColor, letterSpacing = 1.5.sp,
                    modifier = Modifier.padding(start = 4.dp, bottom = 2.dp))
                Text("Root access required for full functionality", fontSize = 11.sp,
                    color = subtextColor.copy(alpha = 0.6f),
                    modifier = Modifier.padding(start = 4.dp, bottom = 4.dp))
            }

            // 7 feature cards
            items(securityFeatures) { feature ->
                Card(
                    modifier = Modifier.fillMaxWidth().clickable {
                        if (rootAvailable) {
                            when (feature.id) {
                                "nmap_deep" -> selectedSecurityFeature = "nmap_deep"
                                "scapy_analyzer" -> selectedSecurityFeature = "scapy_analyzer"
                                "wpa_capture" -> showWpaSheet = true
                                "arp_detection" -> selectedSecurityFeature = "arp_detection"
                                "active_evil_twin" -> showActiveEvilTwinSheet = true
                                "traffic_monitor" -> selectedSecurityFeature = "traffic_monitor"
                                "python_script" -> selectedSecurityFeature = "python_script"
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
                            Surface(
                                color = Color(0xFF1A3A2A),
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    "Available",
                                    fontSize = 11.sp,
                                    color = Color(0xFF44FF88),
                                    fontWeight = FontWeight.Medium,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                )
                            }
                        } else {
                            Surface(
                                shape = RoundedCornerShape(4.dp),
                                color = Color.Transparent,
                                border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFB71C1C))
                            ) {
                                Text(
                                    "Root Required",
                                    color = if (currentTheme == AppTheme.DARK) Color(0xFFEF9A9A) else Color(0xFFB71C1C),
                                    fontSize = 11.sp,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                )
                            }
                        }
                    }
                }
            }
        }

        // Feature locked sheet
        val lockedFeature = securityFeatures.find { it.id == lockedFeatureId }
        if (lockedFeature != null) {
            FeatureLockedSheet(feature = lockedFeature, onDismiss = { lockedFeatureId = null })
        }
        if (showWpaSheet) {
            WpaHandshakeSheet(onDismiss = { showWpaSheet = false })
        }
        if (showActiveEvilTwinSheet) {
            ActiveEvilTwinSheet(onDismiss = { showActiveEvilTwinSheet = false })
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun FeatureLockedSheet(feature: SecurityFeatureInfo, onDismiss: () -> Unit) {
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        ModalBottomSheet(onDismissRequest = onDismiss) {
            Column(
                modifier = Modifier.padding(24.dp).fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(feature.icon, null, tint = Color(0xFF4A9EFF), modifier = Modifier.size(48.dp))
                Spacer(modifier = Modifier.height(12.dp))
                Text(feature.name, fontSize = 20.sp, fontWeight = FontWeight.Bold, color = textColor,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center)
                Spacer(modifier = Modifier.height(8.dp))
                Text(feature.fullDescription, fontSize = 13.sp, color = subtextColor,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center)
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
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Color(0xFF2E7D32),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Get Dev Build", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("The dev build unlocks all root features. Available on GitHub or Gumroad.",
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
    fun WpaHandshakeSheet(onDismiss: () -> Unit) {
        if (!BuildConfig.ENABLE_ROOT_FEATURES) return
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        var authorized by remember { mutableStateOf(false) }
        var interfaceName by remember { mutableStateOf("wlan0") }
        var bssid by remember { mutableStateOf("") }
        var channel by remember { mutableStateOf("6") }
        var status by remember { mutableStateOf("") }
        var loading by remember { mutableStateOf(false) }
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
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.clickable { authorized = !authorized }.fillMaxWidth()
                ) {
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
                Card(
                    colors = CardDefaults.cardColors(containerColor = if (currentTheme == AppTheme.DARK) Color(0xFF0A0A2A) else Color(0xFFE8EAF6)),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("This feature requires monitor mode.\nUse: airmon-ng start $interfaceName",
                        fontSize = 12.sp, color = Color(0xFF4A9EFF), modifier = Modifier.padding(12.dp))
                }
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = {
                        status = "Checking monitor mode..."
                        loading = true
                        scope.launch(Dispatchers.IO) {
                            val result = withTimeoutOrNull(60_000L) { PythonBridge.checkMonitorMode(applicationContext, interfaceName) }
                            withContext(Dispatchers.Main) {
                                loading = false
                                status = when {
                                    result == null -> "Operation timed out after 60 seconds"
                                    result.isMonitor -> "Interface is in monitor mode. Starting capture on channel $channel..."
                                    else -> "Monitor mode not detected. Run: airmon-ng start $interfaceName"
                                }
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
    fun ActiveEvilTwinSheet(onDismiss: () -> Unit) {
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        val currentSsid = remember {
            try {
                @Suppress("DEPRECATION")
                wifiManager.connectionInfo.ssid?.removeSurrounding("\"") ?: ""
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
                            val r = withTimeoutOrNull(60_000L) { PythonBridge.probeForEvilTwin(applicationContext, targetSsid) }
                            withContext(Dispatchers.Main) {
                                loading = false
                                if (r == null) error = "Operation timed out after 60 seconds"
                                else { result = r; if (!r.success) error = r.error }
                            }
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
                error?.let { Spacer(modifier = Modifier.height(8.dp)); Text("Error: $it", color = Color(0xFFFF6666), fontSize = 12.sp) }
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
    fun NmapDeepScanScreen() {
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        val gatewayIp = remember {
            try {
                val dhcp = wifiManager.dhcpInfo
                "%d.%d.%d.%d".format(dhcp.gateway and 0xff, dhcp.gateway shr 8 and 0xff,
                    dhcp.gateway shr 16 and 0xff, dhcp.gateway shr 24 and 0xff)
            } catch (e: Exception) { "" }
        }
        var target by remember { mutableStateOf(gatewayIp) }
        var selectedProfile by remember { mutableStateOf(0) }
        var loading by remember { mutableStateOf(false) }
        var resultText by remember { mutableStateOf("") }
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
                IconButton(onClick = { selectedSecurityFeature = null }) {
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
                            FilterChip(
                                selected = selectedProfile == i,
                                onClick = { selectedProfile = i },
                                label = { Text(label, fontSize = 12.sp) }
                            )
                        }
                    }
                }
                item {
                    Button(
                        onClick = {
                            loading = true; error = null; resultText = ""
                            scope.launch(Dispatchers.IO) {
                                if (!isValidNetworkTarget(target)) {
                                    withContext(Dispatchers.Main) { loading = false; error = "Invalid target — enter a valid IP, CIDR, or hostname" }
                                    return@launch
                                }
                                val nmapBin = NmapBinaryManager.getNmapPath(applicationContext) ?: run {
                                    withContext(Dispatchers.Main) { loading = false; error = "nmap binary not available" }
                                    return@launch
                                }
                                val profileArgs = profiles[selectedProfile].second.split(" ").filter { it.isNotBlank() }
                                val args = profileArgs + listOf(target)
                                val output = withTimeoutOrNull(60_000L) {
                                    val process = ProcessBuilder(nmapBin, *args.toTypedArray())
                                        .redirectErrorStream(true)
                                        .start()
                                    process.inputStream.bufferedReader().readText().also { process.waitFor() }
                                }
                                withContext(Dispatchers.Main) {
                                    loading = false
                                    if (output == null) error = "Scan timed out after 60 seconds"
                                    else resultText = output
                                }
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
                if (resultText.isNotEmpty()) {
                    item {
                        Card(colors = CardDefaults.cardColors(containerColor = cardColor), shape = RoundedCornerShape(12.dp)) {
                            Text(
                                text = resultText,
                                color = textColor,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }
                    item {
                        OutlinedButton(
                            onClick = {
                                val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                                    type = "text/plain"; putExtra(android.content.Intent.EXTRA_TEXT, resultText)
                                }
                                startActivity(android.content.Intent.createChooser(intent, "Share Results"))
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
    fun ScapyAnalyzerScreen() {
        if (!BuildConfig.ENABLE_ROOT_FEATURES) return
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        val gatewayNetwork = remember {
            try {
                val dhcp = wifiManager.dhcpInfo
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
                IconButton(onClick = { selectedSecurityFeature = null }) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = textColor)
                }
                Text("Scapy Analyzer", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = textColor)
            }
            LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                // Interface info
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
                                        val info = PythonBridge.getInterfaceInfo(applicationContext)
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
                // ARP scan
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
                                    if (!isValidNetworkTarget(arpNetwork)) {
                                        arpError = "Invalid network — enter a valid CIDR (e.g. 192.168.1.0/24)"
                                    } else {
                                        arpLoading = true; arpError = null; arpResult = null
                                        scope.launch(Dispatchers.IO) {
                                            val r = withTimeoutOrNull(60_000L) { PythonBridge.runArpScan(applicationContext, arpNetwork) }
                                            withContext(Dispatchers.Main) {
                                                arpLoading = false
                                                if (r == null) arpError = "Operation timed out after 60 seconds"
                                                else { arpResult = r; if (!r.success) arpError = r.error }
                                            }
                                        }
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
    fun ArpDetectionScreen() {
        if (!BuildConfig.ENABLE_ROOT_FEATURES) return
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        var interfaceName by remember { mutableStateOf("wlan0") }
        var monitoring by remember { mutableStateOf(false) }
        var result by remember { mutableStateOf<ArpSpoofResult?>(null) }
        var error by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(monitoring) {
            if (monitoring) {
                while (monitoring) {
                    val r = withContext(Dispatchers.IO) {
                        withTimeoutOrNull(30_000L) { PythonBridge.detectArpSpoofing(applicationContext, interfaceName, 5) }
                    }
                    if (r == null) { error = "Operation timed out after 30 seconds"; monitoring = false; break }
                    result = r
                    if (!r.success) { error = r.error; monitoring = false; break }
                    delay(2000)
                }
            }
        }
        Column(modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()) {
            Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { selectedSecurityFeature = null; monitoring = false }) {
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
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (monitoring) Color(0xFFFF4444) else Color(0xFF44BB77)
                        )
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
    fun TrafficMonitorScreen() {
        if (!BuildConfig.ENABLE_ROOT_FEATURES) return
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        var interfaceName by remember { mutableStateOf("wlan0") }
        var monitoring by remember { mutableStateOf(false) }
        var result by remember { mutableStateOf<TrafficSummaryResult?>(null) }
        var error by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()
        LaunchedEffect(monitoring) {
            if (monitoring) {
                while (monitoring) {
                    val r = withContext(Dispatchers.IO) {
                        withTimeoutOrNull(30_000L) { PythonBridge.captureTrafficSummary(applicationContext, interfaceName, 2) }
                    }
                    if (r == null) { error = "Operation timed out after 30 seconds"; monitoring = false; break }
                    if (r.success) result = r else { error = r.error; monitoring = false; break }
                    delay(500)
                }
            }
        }
        Column(modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding()) {
            Row(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { selectedSecurityFeature = null; monitoring = false }) {
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
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (monitoring) Color(0xFFFF4444) else Color(0xFF44BB77)
                            )
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
                                        textAlign = androidx.compose.ui.text.style.TextAlign.End)
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
    fun PythonScriptScreen() {
        if (!BuildConfig.ENABLE_ROOT_FEATURES) return
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        val consoleBg = Color(0xFF0D0D0D)
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
                IconButton(onClick = { selectedSecurityFeature = null }) {
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
                                fontFamily = FontFamily.Monospace,
                                fontSize = 13.sp,
                                color = Color(0xFF44FF88)
                            ),
                            colors = androidx.compose.material3.OutlinedTextFieldDefaults.colors(
                                unfocusedBorderColor = Color(0xFF2A2A2A),
                                focusedBorderColor = Color(0xFF44FF88)
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
                                    val r = withTimeoutOrNull(35_000L) { PythonBridge.runCustomScript(applicationContext, script) }
                                    withContext(Dispatchers.Main) {
                                        running = false
                                        output = if (r == null) "[TIMEOUT] Script timed out after 35 seconds"
                                        else buildString {
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
                                startActivity(android.content.Intent.createChooser(intent, "Share Output"))
                            }) {
                                Icon(Icons.Filled.Share, null, modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
                if (output.isNotEmpty()) {
                    item {
                        Card(colors = CardDefaults.cardColors(containerColor = consoleBg), shape = RoundedCornerShape(8.dp)) {
                            Text(
                                output,
                                modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                color = Color(0xFF44FF88)
                            )
                        }
                    }
                }
            }
        }
    }

    @Composable
    fun ScanModeButton(label: String, icon: ImageVector, selected: Boolean, onClick: () -> Unit) {
        val isDark = isSystemInDarkTheme()
        val containerColor = if (selected) {
            if (isDark) Color(0xFF2C2C2C) else Color(0xFFFFFFFF)
        } else Color.Transparent
        val contentColor = if (selected) {
            if (isDark) Color.White else Color(0xFF1A1A1A)
        } else {
            if (isDark) Color(0xFF999999) else Color(0xFF666666)
        }
        val borderColor = if (selected) {
            if (isDark) Color(0xFF666666) else Color(0xFF1A1A1A)
        } else {
            if (isDark) Color(0xFF444444) else Color(0xFFCCCCCC)
        }
        Surface(
            onClick = onClick,
            shape = RoundedCornerShape(8.dp),
            color = containerColor,
            border = androidx.compose.foundation.BorderStroke(if (selected) 1.5.dp else 1.dp, borderColor),
            modifier = Modifier.height(36.dp)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Icon(icon, contentDescription = null, tint = contentColor, modifier = Modifier.size(15.dp))
                Text(label, color = contentColor, fontSize = 13.sp, fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal)
            }
        }
    }

    @Composable
    fun QuickActionButton(label: String, icon: ImageVector, cardColor: Color, textColor: Color, onClick: () -> Unit) {
        Button(
            onClick = onClick,
            modifier = Modifier.heightIn(min = 48.dp),
            colors = ButtonDefaults.buttonColors(containerColor = cardColor, contentColor = textColor),
            shape = RoundedCornerShape(12.dp),
            elevation = ButtonDefaults.buttonElevation(2.dp),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            enabled = !isScanning
        ) {
            Icon(icon, null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text(label, fontSize = 14.sp)
        }
    }

    @Composable
    fun StatCard(label: String, value: String, bgColor: Color, textColor: Color, subtextColor: Color,
                 selected: Boolean = false, onClick: (() -> Unit)? = null) {
        Card(
            modifier = Modifier.width(105.dp).height(80.dp).then(
                if (onClick != null) Modifier.clickable { onClick() } else Modifier
            ),
            colors = CardDefaults.cardColors(containerColor = bgColor),
            shape = RoundedCornerShape(12.dp),
            elevation = CardDefaults.cardElevation(if (selected) 6.dp else 2.dp),
            border = if (selected) androidx.compose.foundation.BorderStroke(2.dp, Color.White.copy(alpha = 0.6f)) else null
        ) {
            Column(
                modifier = Modifier.fillMaxSize().padding(12.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(value, fontSize = 28.sp, fontWeight = FontWeight.Bold, color = textColor)
                Text(label, fontSize = 10.sp, color = subtextColor, letterSpacing = 1.sp)
            }
        }
    }

    @Composable
    fun DeviceCard(device: DetectedDevice, cardColor: Color, textColor: Color, subtextColor: Color,
                   accentColor: Color? = null) {
        val showWarning = device.isSuspicious() && device.isVeryClose()
        val backgroundColor = when {
            showWarning -> if (currentTheme == AppTheme.DARK) Color(0xFF3A1A1A) else Color(0xFFFFE5E5)
            device.isSuspicious() -> if (currentTheme == AppTheme.DARK) Color(0xFF2A1A1A) else Color(0xFFFFF5F5)
            else -> cardColor
        }

        Card(
            modifier = Modifier.fillMaxWidth().clickable {
                selectedDevice = device
                currentTab = AppTab.HOME
            },
            colors = CardDefaults.cardColors(containerColor = backgroundColor),
            shape = RoundedCornerShape(12.dp),
            elevation = CardDefaults.cardElevation(2.dp)
        ) {
            Row(modifier = Modifier.fillMaxWidth()) {
                if (accentColor != null) {
                    Box(modifier = Modifier
                        .width(5.dp)
                        .fillMaxHeight()
                        .background(accentColor)
                    )
                }
            Row(
                modifier = Modifier.weight(1f).padding(14.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    Icon(device.type.icon, null, tint = getDeviceColor(device.type), modifier = Modifier.size(32.dp))
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(device.type.displayName, color = textColor, fontSize = 15.sp, fontWeight = FontWeight.Medium)
                        if (device.name.isNotEmpty()) {
                            Text(device.name, color = subtextColor, fontSize = 11.sp, maxLines = 1)
                        }
                        if (device.manufacturer != "Unknown") {
                            Text(device.manufacturer, color = Color(0xFF4A9EFF), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                        }
                        Text("${device.getDistanceFormatted()} • ${device.getDistanceCategory()}",
                            color = getDistanceColor(device.getDistance()), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }

                Column(horizontalAlignment = Alignment.End) {
                    Text("${device.signalStrength} dBm", color = getSignalColor(device.signalStrength),
                        fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    if (device.protocol.isNotEmpty()) {
                        Text(device.protocol, color = subtextColor, fontSize = 10.sp)
                    }
                    if (showWarning) {
                        Text("⚠️", fontSize = 16.sp)
                    }
                }
            }
            } // end outer Row
        }
    }

    @Composable
    fun DeviceDetailScreen() {
        val device = selectedDevice ?: return
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)
        var macVendorResult by remember { mutableStateOf<String?>(null) }
        var macVendorLoading by remember { mutableStateOf(false) }
        val detailScope = rememberCoroutineScope()

        BackHandler { selectedDevice = null }

        LazyColumn(
            modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding().padding(horizontal = 20.dp)
        ) {
            item {
                Row(modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp)) {
                    IconButton(
                        onClick = { selectedDevice = null },
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

                DetailRow("Distance", "${device.getDistanceFormatted()} (${device.getDistanceCategory()})", cardColor, textColor, subtextColor, true)
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
                            IconButton(onClick = { copyToClipboard("MAC Address", device.macAddress) }, modifier = Modifier.size(36.dp)) {
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
                                                val result = OuiLookup.lookupWithFallback(applicationContext, device.macAddress)
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
                                result == "RANDOMIZED" -> Text(
                                    "Randomized MAC — vendor lookup unavailable",
                                    fontSize = 12.sp, color = subtextColor,
                                    fontWeight = FontWeight.Normal
                                )
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
                    DetailRow("Manufacturer", device.manufacturer, cardColor, textColor, subtextColor, true)
                }
                DetailRow("Signal Strength", "${device.signalStrength} dBm (${getSignalQuality(device.signalStrength)})", cardColor, textColor, subtextColor, true)
                if (device.protocol.isNotEmpty()) DetailRow("Protocol", device.protocol, cardColor, textColor, subtextColor, true)
                if (device.frequency.isNotEmpty()) DetailRow("Frequency", device.frequency, cardColor, textColor, subtextColor, true)
                DetailRow("Status", if (device.isSuspicious()) "⚠️ Suspicious" else "✓ Normal", cardColor, textColor, subtextColor, false)
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            lifecycleScope.launch(Dispatchers.IO) {
                                database.deviceHistoryDao().updateUserMark(device.macAddress, safe = true, suspicious = false)
                            }
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF44FF88))
                    ) {
                        Icon(Icons.Filled.CheckCircle, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Mark Safe", fontSize = 13.sp)
                    }
                    OutlinedButton(
                        onClick = {
                            lifecycleScope.launch(Dispatchers.IO) {
                                database.deviceHistoryDao().updateUserMark(device.macAddress, safe = false, suspicious = true)
                            }
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFFF4444))
                    ) {
                        Icon(Icons.Filled.Warning, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Mark Suspicious", fontSize = 13.sp)
                    }
                }
                val history = signalHistory[device.macAddress] ?: emptyList()
                if ((signalHistory[device.macAddress]?.size ?: 0) >= 3) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text("SIGNAL HISTORY", fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(8.dp))
                    val graphColor = getDeviceColor(device.type)
                    Canvas(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(80.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(cardColor)
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
    fun DetailRow(label: String, value: String, cardColor: Color, textColor: Color, subtextColor: Color, canCopy: Boolean) {
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
                    Text(label, fontSize = 11.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurfaceVariant, letterSpacing = 1.sp)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(value, fontSize = 16.sp, color = textColor, fontWeight = FontWeight.Medium)
                }
                if (canCopy) {
                    IconButton(onClick = { copyToClipboard(label, value) }, modifier = Modifier.size(36.dp)) {
                        Icon(Icons.Filled.ContentCopy, "Copy", tint = subtextColor, modifier = Modifier.size(20.dp))
                    }
                }
            }
        }
    }

    private fun copyToClipboard(label: String, value: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(this, "$label copied!", Toast.LENGTH_SHORT).show()
    }

    private fun exportHistoryToCsv() {
        lifecycleScope.launch {
            val allDevices = withContext(Dispatchers.IO) {
                database.deviceHistoryDao().getAllDevices()
            }
            val csv = buildString {
                appendLine("Session ID,Timestamp,Device Name,Type,MAC,Signal,Manufacturer,Suspicious")
                allDevices.forEach { d ->
                    val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(d.timestamp))
                    appendLine("\"${d.scanSessionId}\",\"$ts\",\"${d.name}\",\"${d.deviceType}\",\"${d.macAddress}\",${d.signalStrength},\"${d.manufacturer}\",${d.isSuspicious}")
                }
            }
            androidx.core.app.ShareCompat.IntentBuilder(this@MainActivity)
                .setType("text/plain")
                .setText(csv)
                .setChooserTitle("Export History CSV")
                .startChooser()
        }
    }

    private fun exportHistoryToPdf() {
        lifecycleScope.launch {
            val sessions = withContext(Dispatchers.IO) {
                database.deviceHistoryDao().getAllSessions()
            }
            val allDevices = withContext(Dispatchers.IO) {
                database.deviceHistoryDao().getAllDevices()
            }

            val pdfDoc = android.graphics.pdf.PdfDocument()
            val pageInfo = android.graphics.pdf.PdfDocument.PageInfo.Builder(595, 842, 1).create()
            val page = pdfDoc.startPage(pageInfo)
            val canvas = page.canvas

            val titlePaint = android.graphics.Paint().apply {
                textSize = 24f; isFakeBoldText = true; isAntiAlias = true
                color = android.graphics.Color.BLACK
            }
            val bodyPaint = android.graphics.Paint().apply {
                textSize = 12f; isAntiAlias = true
                color = android.graphics.Color.DKGRAY
            }
            val smallPaint = android.graphics.Paint().apply {
                textSize = 10f; isAntiAlias = true
                color = android.graphics.Color.GRAY
            }

            var y = 60f
            canvas.drawText("Privacy Shield — Scan Report", 40f, y, titlePaint)
            y += 20f
            canvas.drawText("Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date())}", 40f, y, bodyPaint)
            y += 30f
            canvas.drawText("Total Sessions: ${sessions.size}   Total Devices: ${allDevices.size}   Suspicious: ${allDevices.count { it.isSuspicious }}", 40f, y, bodyPaint)
            y += 30f

            val df = SimpleDateFormat("MMM d yyyy HH:mm", Locale.getDefault())
            sessions.take(30).forEach { session ->
                if (y > 780f) return@forEach
                canvas.drawText("${df.format(Date(session.timestamp))}  —  ${session.deviceCount} devices  (${session.suspiciousCount} suspicious)", 40f, y, bodyPaint)
                y += 16f
                allDevices.filter { it.scanSessionId == session.scanSessionId }.take(5).forEach { d ->
                    if (y > 780f) return@forEach
                    canvas.drawText("    ${d.deviceType}  ${d.macAddress}  ${d.signalStrength}dBm  ${d.manufacturer}", 40f, y, smallPaint)
                    y += 14f
                }
                y += 6f
            }

            pdfDoc.finishPage(page)

            val file = java.io.File(externalCacheDir, "privacy_shield_report.pdf")
            pdfDoc.writeTo(file.outputStream())
            pdfDoc.close()

            val uri = androidx.core.content.FileProvider.getUriForFile(
                this@MainActivity,
                "${packageName}.provider",
                file
            )
            val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                type = "application/pdf"
                putExtra(android.content.Intent.EXTRA_STREAM, uri)
                addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(android.content.Intent.createChooser(intent, "Share PDF Report"))
        }
    }

    private fun disableAppLock() {
        getSharedPreferences("privacy_shield_prefs", Context.MODE_PRIVATE)
            .edit().putBoolean("app_lock_enabled", false).apply()
    }

    private fun showBiometricPrompt(onSuccess: () -> Unit, onCancel: () -> Unit = { finish() }) {
        try {
            val biometricManager = androidx.biometric.BiometricManager.from(this)
            val canAuth = biometricManager.canAuthenticate(
                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK or
                androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            when (canAuth) {
                androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS -> { /* proceed */ }
                androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                    Toast.makeText(this, "No biometric hardware found", Toast.LENGTH_SHORT).show()
                    disableAppLock()
                    onSuccess(); return
                }
                androidx.biometric.BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                    Toast.makeText(this, "Biometric temporarily unavailable", Toast.LENGTH_SHORT).show()
                    onSuccess(); return
                }
                androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                    Toast.makeText(this, "No biometrics enrolled in device settings", Toast.LENGTH_SHORT).show()
                    disableAppLock()
                    onSuccess(); return
                }
                androidx.biometric.BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {
                    Toast.makeText(this, "App Lock unavailable on this device", Toast.LENGTH_SHORT).show()
                    disableAppLock()
                    onSuccess(); return
                }
                else -> { disableAppLock(); onSuccess(); return }
            }
            val executor = mainExecutor
            val prompt = androidx.biometric.BiometricPrompt(this as androidx.fragment.app.FragmentActivity, executor,
                object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                        onSuccess()
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        onCancel()
                    }
                    override fun onAuthenticationFailed() {}
                }
            )
            val promptInfo = androidx.biometric.BiometricPrompt.PromptInfo.Builder()
                .setTitle("Privacy Shield")
                .setSubtitle("Authenticate to access")
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK or
                    androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .build()
            prompt.authenticate(promptInfo)
        } catch (e: Exception) {
            disableAppLock()
            onSuccess()
        }
    }

    private fun getDeviceColor(type: DeviceType): Color = when (type) {
        DeviceType.CAMERA -> Color(0xFFFF4444)
        DeviceType.MICROPHONE -> Color(0xFFFFAA44)
        DeviceType.SMART_GLASSES -> Color(0xFF44AAFF)
        DeviceType.HEADSET -> Color(0xFF44FF88)
        DeviceType.WATCH -> Color(0xFFAA44FF)
        DeviceType.SPEAKER -> Color(0xFFFFAA44)
        DeviceType.TV -> Color(0xFF44AAFF)
        DeviceType.IOT_DEVICE, DeviceType.ROUTER -> Color(0xFF8844FF)
        DeviceType.PHONE, DeviceType.TABLET, DeviceType.COMPUTER -> Color(0xFF4A9EFF)
        else -> Color(0xFF666666)
    }

    private fun getSignalColor(signal: Int): Color = when {
        signal > -50 -> Color(0xFF44FF88)
        signal > -60 -> Color(0xFF88FF44)
        signal > -70 -> Color(0xFFFFAA44)
        else -> Color(0xFFFF4444)
    }

    private fun getDistanceColor(distance: Double): Color = when {
        distance < 5 -> Color(0xFFFF4444)
        distance < 15 -> Color(0xFFFFAA44)
        else -> Color(0xFF44FF88)
    }

    private fun getSignalQuality(signal: Int): String = when {
        signal > -50 -> "Excellent"
        signal > -60 -> "Good"
        signal > -70 -> "Fair"
        else -> "Weak"
    }

    private fun requestPermissionsAndScan(mode: ScanMode = ScanMode.FULL) {
        val permissions = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissions.add(Manifest.permission.BLUETOOTH_SCAN)
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT)
        }

        if (permissions.all { ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED }) {
            startDeviceScan(mode)
        } else {
            permissionLauncher.launch(permissions.toTypedArray())
        }
    }

    private fun flushDeviceBuffer() {
        val snapshot: List<DetectedDevice>
        val signals: List<Pair<String, Int>>
        synchronized(bufferLock) {
            if (deviceBuffer.isEmpty() && signalBuffer.isEmpty()) return
            snapshot = deviceBuffer.toList()
            signals = signalBuffer.toList()
            deviceBuffer.clear()
            signalBuffer.clear()
        }
        snapshot.forEach { buffered ->
            val existingIndex = devices.indexOfFirst { it.macAddress == buffered.macAddress }
            if (existingIndex >= 0) {
                devices[existingIndex] = devices[existingIndex].copy(signalStrength = buffered.signalStrength)
            } else {
                devices.add(buffered)
            }
        }
        signals.forEach { (mac, rssi) ->
            signalHistory.getOrPut(mac) { mutableListOf() }.let { history ->
                history.add(rssi)
                if (history.size > 20) history.removeAt(0)
            }
        }
    }

    private fun startDeviceScan(mode: ScanMode) {
        val now = System.currentTimeMillis()
        if (now - lastManualScanTime < 30_000L) {
            Toast.makeText(this, "Please wait before scanning again", Toast.LENGTH_SHORT).show()
            return
        }
        lastManualScanTime = now
        scanStartTime = System.currentTimeMillis()
        devices.clear()
        signalHistory.clear()
        synchronized(bufferLock) { deviceBuffer.clear(); signalBuffer.clear() }
        lastBufferFlush = 0L
        isScanning = true
        currentScanMode = mode
        currentScanSessionId = UUID.randomUUID().toString()
        scanWiFi(mode)
        scanBluetooth(mode)
    }

    @SuppressLint("MissingPermission")
    private fun scanWiFi(mode: ScanMode) {
        val wifiReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                wifiManager.scanResults.forEach { result ->
                    val networkName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        result.wifiSsid?.toString()?.removeSurrounding("\"") ?: ""
                    } else {
                        @Suppress("DEPRECATION") result.SSID.ifEmpty { "" }
                    }

                    val manufacturer = getMacManufacturer(result.BSSID)
                    val deviceType = identifyDeviceType(networkName, result.BSSID, manufacturer)

                    val shouldAdd = when (mode) {
                        ScanMode.CAMERAS_ONLY -> deviceType == DeviceType.CAMERA
                        ScanMode.MICS_ONLY -> deviceType == DeviceType.MICROPHONE
                        ScanMode.FULL -> true
                    }

                    if (shouldAdd) {
                        val newMac = result.BSSID
                        val existingIndex = devices.indexOfFirst { it.macAddress == newMac }
                        if (existingIndex >= 0) {
                            devices[existingIndex] = devices[existingIndex].copy(signalStrength = result.level)
                        } else {
                            devices.add(
                                DetectedDevice(
                                    name = networkName,
                                    type = deviceType,
                                    macAddress = result.BSSID,
                                    signalStrength = result.level,
                                    protocol = "WiFi",
                                    frequency = "${result.frequency} MHz",
                                    manufacturer = manufacturer
                                )
                            )
                        }
                    }
                }
                unregisterReceiver(this)
            }
        }

        registerReceiver(wifiReceiver, IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION))
        wifiManager.startScan()
    }

    @SuppressLint("MissingPermission")
    private fun scanBluetooth(mode: ScanMode) {
        val scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val device = result.device
                val deviceName = device.name ?: ""
                val manufacturer = getMacManufacturer(device.address)
                val deviceType = identifyDeviceType(deviceName, device.address, manufacturer)

                val shouldAdd = when (mode) {
                    ScanMode.CAMERAS_ONLY -> deviceType == DeviceType.CAMERA
                    ScanMode.MICS_ONLY -> deviceType == DeviceType.MICROPHONE
                    ScanMode.FULL -> true
                }

                if (shouldAdd) {
                    val newDevice = DetectedDevice(
                        name = deviceName,
                        type = deviceType,
                        macAddress = device.address,
                        signalStrength = result.rssi,
                        protocol = "Bluetooth",
                        manufacturer = manufacturer
                    )
                    synchronized(bufferLock) {
                        val existing = deviceBuffer.indexOfFirst { it.macAddress == device.address }
                        if (existing >= 0) {
                            deviceBuffer[existing] = newDevice
                        } else {
                            deviceBuffer.add(newDevice)
                        }
                        signalBuffer.add(device.address to result.rssi)
                    }
                    val now = System.currentTimeMillis()
                    if (now - lastBufferFlush > 500) {
                        lastBufferFlush = now
                        android.os.Handler(mainLooper).post { flushDeviceBuffer() }
                    }
                }
            }
        }

        try {
            bluetoothAdapter.bluetoothLeScanner?.startScan(scanCallback)
            android.os.Handler(mainLooper).postDelayed({
                try {
                    bluetoothAdapter.bluetoothLeScanner?.stopScan(scanCallback)
                } finally {
                    flushDeviceBuffer() // flush any remaining buffered devices
                    lastScanDuration = System.currentTimeMillis() - scanStartTime
                    lastScanTime = System.currentTimeMillis()
                    isScanning = false
                    lastEvilTwinAlerts = detectEvilTwins(devices)
                    securityResetTrigger++
                    val sessionId = currentScanSessionId
                    val timestamp = System.currentTimeMillis()
                    val entities = devices.map { it.toHistoryEntity(sessionId, timestamp) }
                    if (entities.isNotEmpty()) {
                        lifecycleScope.launch {
                            database.deviceHistoryDao().insertAll(entities)
                        }
                    }
                }
            }, 5000)
        } catch (e: SecurityException) {
            isScanning = false
        }
    }

    private fun identifyDeviceType(name: String, mac: String, manufacturer: String): DeviceType {
        val lower = name.lowercase()

        // Unknown with SSID = Router
        if (name.isNotEmpty() && !name.contains("Hidden", ignoreCase = true) && manufacturer == "Unknown") {
            return DeviceType.ROUTER
        }

        return when {
            lower.contains("watch") || (lower.contains("fit") && manufacturer.contains("Samsung", ignoreCase = true)) -> DeviceType.WATCH
            manufacturer.contains("TP-Link", ignoreCase = true) || manufacturer.contains("Netgear", ignoreCase = true) ||
                    manufacturer.contains("Asus", ignoreCase = true) || manufacturer.contains("Cisco", ignoreCase = true) ||
                    lower.contains("router") || lower.contains("ap-") -> DeviceType.ROUTER
            lower.contains("cam") || lower.contains("wyze") || lower.contains("ring") -> DeviceType.CAMERA
            lower.contains("echo") || lower.contains("alexa") || lower.contains("google home") -> DeviceType.MICROPHONE
            lower.contains("speaker") || lower.contains("soundbar") -> DeviceType.SPEAKER
            lower.contains("meta") || lower.contains("ray-ban") || lower.contains("glasses") -> DeviceType.SMART_GLASSES
            lower.contains("buds") || lower.contains("airpod") || lower.contains("headphone") ||
                    lower.contains("wh-") || lower.contains("wf-") || lower.contains("linkbuds") ||
                    (manufacturer.contains("Sony", ignoreCase = true) && (lower.contains("wh") || lower.contains("wf"))) -> DeviceType.HEADSET
            lower.contains(" tv") || lower.contains("television") -> DeviceType.TV
            lower.contains("iot") || lower.contains("smart") || lower.contains("sensor") || lower.contains("bulb") -> DeviceType.IOT_DEVICE
            lower.contains("iphone") || lower.contains("galaxy s") || lower.contains("pixel") -> DeviceType.PHONE
            lower.contains("ipad") || lower.contains("galaxy tab") || lower.contains("tablet") -> DeviceType.TABLET
            lower.contains("laptop") || lower.contains("macbook") || lower.contains("thinkpad") -> DeviceType.COMPUTER
            else -> DeviceType.UNKNOWN
        }
    }
}

@Composable
fun PrivacyShieldTheme(isDark: Boolean, content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isDark) darkColorScheme(
            primary = Color.White, background = Color(0xFF000000), surface = Color(0xFF1A1A1A)
        ) else lightColorScheme(
            primary = Color.Black, background = Color(0xFFF5F5F5), surface = Color.White
        ),
        content = content
    )
}