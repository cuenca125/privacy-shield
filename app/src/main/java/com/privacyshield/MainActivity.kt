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
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
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

data class DetectedDevice(
    val name: String,
    val type: DeviceType,
    val macAddress: String,
    var signalStrength: Int,
    val protocol: String,
    val frequency: String = "",
    val manufacturer: String = "Unknown",
    val id: String = macAddress
) {
    fun getDistance(): Double {
        val freq = if (protocol == "WiFi" && frequency.isNotEmpty()) {
            frequency.replace(" MHz", "").toDoubleOrNull() ?: 2400.0
        } else 2400.0

        val fspl = 27.55 - (20 * kotlin.math.log10(freq)) + Math.abs(signalStrength.toDouble())
        return 10.0.pow(fspl / 20.0)
    }

    fun getDistanceCategory(): String = when {
        getDistance() < 5 -> "Near"
        getDistance() < 15 -> "Medium"
        else -> "Far"
    }

    fun getDistanceFormatted(): String {
        val distance = getDistance()
        return when {
            distance < 1 -> "<1m"
            distance < 10 -> "${distance.toInt()}m"
            else -> "${(distance / 10).toInt() * 10}m+"
        }
    }

    fun isSuspicious(): Boolean = when (type) {
        DeviceType.CAMERA, DeviceType.MICROPHONE -> true
        DeviceType.ROUTER -> false
        DeviceType.UNKNOWN -> manufacturer == "Unknown"
        else -> false
    }

    fun isVeryClose(): Boolean = getDistance() < 3
}

enum class DeviceType(val displayName: String, val icon: ImageVector) {
    CAMERA("Camera", Icons.Filled.Videocam),
    MICROPHONE("Microphone", Icons.Filled.Mic),
    HEADSET("Earbuds/Headset", Icons.Filled.Headphones),
    WATCH("Smartwatch", Icons.Filled.Watch),
    SMART_GLASSES("Smart Glasses", Icons.Filled.RemoveRedEye),
    IOT_DEVICE("IoT Device", Icons.Filled.Sensors),
    PHONE("Phone", Icons.Filled.PhoneAndroid),
    TABLET("Tablet", Icons.Filled.Tablet),
    COMPUTER("Computer", Icons.Filled.Computer),
    ROUTER("Router", Icons.Filled.Router),
    SPEAKER("Speaker", Icons.Filled.Speaker),
    TV("Smart TV", Icons.Filled.Tv),
    UNKNOWN("Unknown Device", Icons.Filled.Help)
}

data class PortScanResult(val ip: String, val timestamp: Long, val openPorts: List<Int>)
data class TraceHop(val hop: Int, val ip: String, val ms: Long, val timedOut: Boolean)

data class CveResult(
    val id: String,
    val summary: String,
    val cvss: Double?,
    val published: String,
    val references: List<String>,
    val source: String = "CIRCL"
)

data class EvilTwinAlert(
    val ssid: String,
    val reason: String,
    val device1Mac: String,
    val device2Mac: String?,
    val signalStrength: Int
)

fun getCveSeverity(cvss: Double?): Pair<String, Color> = when {
    cvss == null -> "UNKNOWN" to Color(0xFF888888)
    cvss >= 9.0 -> "CRITICAL" to Color(0xFFFF4444)
    cvss >= 7.0 -> "HIGH" to Color(0xFFFF8844)
    cvss >= 4.0 -> "MEDIUM" to Color(0xFFE6A817)  // darker amber — sufficient contrast on both light/dark
    else -> "LOW" to Color(0xFF44BB77)
}

enum class AppTheme { LIGHT, DARK }
enum class ScanMode { FULL, CAMERAS_ONLY, MICS_ONLY }
enum class AppTab { HOME, SEARCH, NETWORK, TOOLS, SECURITY }

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
        Box(modifier = Modifier.fillMaxSize()) {
            Scaffold(bottomBar = { BottomNavigationBar() }) { paddingValues ->
                Box(modifier = Modifier.padding(paddingValues)) {
                    when (currentTab) {
                        AppTab.HOME -> if (selectedDevice == null) HomeTab() else DeviceDetailScreen()
                        AppTab.SEARCH -> SearchTab()
                        AppTab.NETWORK -> NetworkTab()
                        AppTab.TOOLS -> ToolsTab()
                        AppTab.SECURITY -> SecurityTab()
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
            Triple(Icons.Filled.NetworkCheck, "Network Analysis", "Analyze your network, discover hosts, check DNS security"),
            Triple(Icons.Filled.Build, "Security Tools", "Port scanner, ping, WHOIS lookup and traceroute built in")
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
        val selectedColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val unselectedColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)

        NavigationBar(
            containerColor = bgColor,
            modifier = Modifier.navigationBarsPadding()
        ) {
            listOf(
                Triple(AppTab.HOME, Icons.Filled.Shield, "Home"),
                Triple(AppTab.SEARCH, Icons.Filled.Search, "Search"),
                Triple(AppTab.NETWORK, Icons.Filled.NetworkCheck, "Network"),
                Triple(AppTab.TOOLS, Icons.Filled.Build, "Tools"),
                Triple(AppTab.SECURITY, Icons.Filled.Security, "Security")
            ).forEach { (tab, icon, label) ->
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
                        val iconTint = if (tab == AppTab.TOOLS && (nmapLoading || serviceLoading)) {
                            val infiniteTransition = rememberInfiniteTransition(label = "toolsScan")
                            val alpha by infiniteTransition.animateFloat(
                                initialValue = 0.6f,
                                targetValue = 1.0f,
                                animationSpec = infiniteRepeatable(
                                    animation = tween(800, easing = LinearEasing),
                                    repeatMode = RepeatMode.Reverse
                                ),
                                label = "scanAlpha"
                            )
                            Color(0xFF4CAF50).copy(alpha = alpha)
                        } else {
                            LocalContentColor.current
                        }
                        Icon(icon, label, tint = iconTint)
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
        nmapLoading = true
        nmapError = null
        nmapResults = null
        lifecycleScope.launch(Dispatchers.IO) {
            val result = PythonBridge.runHostScan(applicationContext, nmapTarget)
            withContext(Dispatchers.Main) {
                nmapResults = result
                nmapLoading = false
                if (!result.success) nmapError = result.error
            }
        }
    }

    fun launchServiceScan(ports: String) {
        if (serviceLoading) return
        serviceLoading = true
        serviceError = null
        serviceResults = null
        lifecycleScope.launch(Dispatchers.IO) {
            val result = PythonBridge.runServiceScan(applicationContext, serviceTarget, ports)
            withContext(Dispatchers.Main) {
                serviceResults = result
                serviceLoading = false
                if (!result.success) serviceError = result.error
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
        val suspiciousDevices = devices.filter { it.isSuspicious() }

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
                        color = textColor, letterSpacing = 2.sp)
                    Text("Device Detection", fontSize = 11.sp, color = subtextColor, letterSpacing = 1.sp)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    IconButton(
                        onClick = { showSettingsSheet = true },
                        modifier = Modifier.size(40.dp).clip(CircleShape).background(cardColor)
                    ) {
                        Icon(Icons.Filled.Settings, "Settings", tint = textColor)
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Privacy Score Card - expanded
            val scoreBorder = when {
                privacyScore >= 80 -> androidx.compose.foundation.BorderStroke(1.dp, Color(0xFF44FF88).copy(alpha = 0.3f))
                privacyScore < 50 -> androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFFF4444).copy(alpha = 0.3f))
                else -> null
            }
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = cardColor),
                shape = RoundedCornerShape(16.dp),
                elevation = CardDefaults.cardElevation(4.dp),
                border = scoreBorder
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    // Row 1: Label left, score number right
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("PRIVACY SCORE", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
                        Text("$privacyScore", fontSize = 48.sp, fontWeight = FontWeight.Bold,
                            color = getPrivacyScoreColor(privacyScore))
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
                    Spacer(modifier = Modifier.height(16.dp))
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
            Text("SCAN MODE", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp,
                modifier = Modifier.padding(bottom = 8.dp))

            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                item { QuickActionButton("Full Scan", Icons.Filled.Search, cardColor, textColor) {
                    currentScanMode = ScanMode.FULL
                    requestPermissionsAndScan(ScanMode.FULL)
                }}
                item { QuickActionButton("Cameras", Icons.Filled.Videocam, cardColor, textColor) {
                    currentScanMode = ScanMode.CAMERAS_ONLY
                    requestPermissionsAndScan(ScanMode.CAMERAS_ONLY)
                }}
                item { QuickActionButton("Mics", Icons.Filled.Mic, cardColor, textColor) {
                    currentScanMode = ScanMode.MICS_ONLY
                    requestPermissionsAndScan(ScanMode.MICS_ONLY)
                }}
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
                        Text(devices.size.toString(), fontSize = 40.sp, fontWeight = FontWeight.Bold, color = Color.White)
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
                        Text(suspiciousDevices.size.toString(), fontSize = 40.sp, fontWeight = FontWeight.Bold, color = Color.White)
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
                        Text((devices.size - suspiciousDevices.size).toString(), fontSize = 40.sp, fontWeight = FontWeight.Bold, color = Color.White)
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
                Text("FILTERS", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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

                // Try circl.lu first
                val circlResults: List<CveResult> = try {
                    val circlJson = withContext(Dispatchers.IO) {
                        val primaryUrl = if (product != null)
                            "https://cve.circl.lu/api/search/$vendor/$product"
                        else "https://cve.circl.lu/api/search/$vendor"
                        try { fetchUrl(primaryUrl) } catch (e: Exception) {
                            if (product != null) fetchUrl("https://cve.circl.lu/api/search/$vendor")
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
                        Text("PORT SCANNER", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                                    if (!isPortScanning) {
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
                                enabled = !isPortScanning && targetIp.isNotEmpty(),
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
                        Text("PING", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                            Text("RECENT SCANS", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                        Text("WHOIS LOOKUP", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                        Text("TRACEROUTE", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                                    if (!isTracing) {
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
                                enabled = !isTracing && traceTarget.isNotEmpty(),
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
                        Text("CVE LOOKUP", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                            Text("PYTHON SCANNER", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp,
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
                            Text("CONNECTED NETWORK", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                        Text("GATEWAY INFO", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                        Text("HOST DISCOVERY", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                        Text("DNS LEAK CHECK", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                            Text("SECURITY ANALYSIS", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
        val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
        val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
        val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)

        Box(modifier = Modifier.fillMaxSize().background(bgColor).statusBarsPadding(),
            contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.padding(horizontal = 32.dp)) {
                Icon(Icons.Filled.Terminal, null, tint = subtextColor, modifier = Modifier.size(64.dp))
                Spacer(modifier = Modifier.height(16.dp))
                Text("Security Tools", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = textColor)
                Spacer(modifier = Modifier.height(8.dp))
                Text("Advanced security testing suite", fontSize = 14.sp, color = subtextColor,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center)
                Spacer(modifier = Modifier.height(4.dp))
                Text("Coming in Phase 4", fontSize = 12.sp, color = Color(0xFF44FF88))
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
                                Text("MAC Address", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                    Text("SIGNAL HISTORY", fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                    Text(label, fontSize = 12.sp, color = subtextColor, letterSpacing = 1.sp)
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
                    val existingIndex = devices.indexOfFirst { it.macAddress == device.address }
                    if (existingIndex >= 0) {
                        devices[existingIndex] = devices[existingIndex].copy(signalStrength = result.rssi)
                    } else {
                        devices.add(
                            DetectedDevice(
                                name = deviceName,
                                type = deviceType,
                                macAddress = device.address,
                                signalStrength = result.rssi,
                                protocol = "Bluetooth",
                                manufacturer = manufacturer
                            )
                        )
                    }
                    signalHistory.getOrPut(device.address) { mutableListOf() }.let { history ->
                        history.add(result.rssi)
                        if (history.size > 20) history.removeAt(0)
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
                    lastScanDuration = System.currentTimeMillis() - scanStartTime
                    lastScanTime = System.currentTimeMillis()
                    isScanning = false
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