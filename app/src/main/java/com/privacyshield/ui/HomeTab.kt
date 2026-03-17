package com.privacyshield.ui

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.LifecycleCoroutineScope
import com.privacyshield.model.AppTab
import com.privacyshield.model.AppTheme
import com.privacyshield.model.DetectedDevice
import com.privacyshield.model.DeviceType
import com.privacyshield.model.ScanMode
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeTab(
    devices: List<DetectedDevice>,
    isScanning: Boolean,
    currentTheme: AppTheme,
    currentScanMode: ScanMode,
    lastScanTime: Long,
    lastScanDuration: Long,
    homeResetTrigger: Int,
    macVendorDatabaseSize: Int,
    backgroundScanEnabled: Boolean,
    onScanModeSelected: (ScanMode) -> Unit,
    onBackgroundScanToggle: (Boolean) -> Unit,
    onScheduleBackgroundScan: () -> Unit,
    onCancelBackgroundScan: () -> Unit,
    onSaveTheme: (AppTheme) -> Unit,
    onCurrentThemeChange: (AppTheme) -> Unit,
    onExportCsv: () -> Unit,
    onClearAllData: () -> Unit,
    onClearOldHistory: () -> Unit,
    onShowBiometricPrompt: (onSuccess: () -> Unit, onCancel: () -> Unit) -> Unit,
    onNavigateToSearch: () -> Unit,
    onSearchSuspiciousOnly: () -> Unit,
    onSearchSafeOnly: () -> Unit,
    searchScrollTrigger: Int,
    onSearchScrollTriggerIncrement: () -> Unit,
    onSearchSuspiciousOnlySet: (Boolean) -> Unit,
    onSearchSafeOnlySet: (Boolean) -> Unit,
    onSelectedFilterSet: (DeviceType?) -> Unit,
    onTabChange: (AppTab) -> Unit,
    calculatePrivacyScore: () -> Int,
    getTimeAgo: (Long) -> String,
    getMostCommonDeviceType: () -> String,
    getNearestThreatDistance: () -> String,
    getPrivacyScoreColor: (Int) -> Color,
    getPrivacyScoreLabel: (Int) -> String,
    prefs: android.content.SharedPreferences,
    lifecycleScope: LifecycleCoroutineScope,
    onDevicesCleared: () -> Unit,
    onBackgroundScanEnabledSet: (Boolean) -> Unit,
    onCurrentTabSet: (AppTab) -> Unit
) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)

    var showSettingsSheet by remember { mutableStateOf(false) }
    var showPrivacyDetailSheet by remember { mutableStateOf(false) }
    val sheetState = rememberModalBottomSheetState()
    var scanIntervalMinutes by remember { mutableStateOf(prefs.getInt("scan_interval_minutes", 15)) }
    var showIntervalDropdown by remember { mutableStateOf(false) }
    var showClearDataDialog by remember { mutableStateOf(false) }
    var selectedStatFilter by remember { mutableStateOf<String?>(null) }
    val homeListState = androidx.compose.foundation.lazy.rememberLazyListState()
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
                onScanModeSelected(ScanMode.FULL)
            }
            ScanModeButton("Cameras", Icons.Filled.Videocam, currentScanMode == ScanMode.CAMERAS_ONLY) {
                onScanModeSelected(ScanMode.CAMERAS_ONLY)
            }
            ScanModeButton("Mics", Icons.Filled.Mic, currentScanMode == ScanMode.MICS_ONLY) {
                onScanModeSelected(ScanMode.MICS_ONLY)
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
                onSearchSuspiciousOnlySet(false)
                onSearchSafeOnlySet(false)
                onSelectedFilterSet(null)
                onCurrentTabSet(AppTab.SEARCH)
                onSearchScrollTriggerIncrement()
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
                onSearchSuspiciousOnlySet(true)
                onSearchSafeOnlySet(false)
                onCurrentTabSet(AppTab.SEARCH)
                onSearchScrollTriggerIncrement()
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
                onSearchSafeOnlySet(true)
                onSearchSuspiciousOnlySet(false)
                onCurrentTabSet(AppTab.SEARCH)
                onSearchScrollTriggerIncrement()
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
        AlertDialog(
            onDismissRequest = { showClearDataDialog = false },
            title = { Text("Clear All App Data", color = dlgTextColor) },
            text = { Text("This will remove all scan history and reset all settings. This cannot be undone.", color = dlgSubColor) },
            confirmButton = {
                TextButton(onClick = {
                    showClearDataDialog = false
                    onClearAllData()
                    onBackgroundScanEnabledSet(false)
                    onCurrentTabSet(AppTab.HOME)
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
                                val newTheme = if (it) AppTheme.DARK else AppTheme.LIGHT
                                onCurrentThemeChange(newTheme)
                                onSaveTheme(newTheme)
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
                                onBackgroundScanEnabledSet(enabled)
                                prefs.edit().putBoolean("background_scan_enabled", enabled).apply()
                                if (enabled) onScheduleBackgroundScan() else onCancelBackgroundScan()
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
                                            prefs.edit().putInt("scan_interval_minutes", mins).apply()
                                            showIntervalDropdown = false
                                            onScheduleBackgroundScan()
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
                        TextButton(onClick = { onClearOldHistory() }) {
                            Text("Clear", color = Color(0xFFFF4444), fontSize = 12.sp)
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // App Lock card
                val biometricContext = androidx.compose.ui.platform.LocalContext.current
                val biometricAvailable = remember {
                    try {
                        val bm = androidx.biometric.BiometricManager.from(biometricContext)
                        bm.canAuthenticate(
                            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK or
                            androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                        ) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
                    } catch (e: Exception) { false }
                }
                var appLockEnabled by remember {
                    mutableStateOf(prefs.getBoolean("app_lock_enabled", false))
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
                                    onShowBiometricPrompt(
                                        {
                                            appLockEnabled = true
                                            prefs.edit().putBoolean("app_lock_enabled", true).apply()
                                        },
                                        {}
                                    )
                                } else {
                                    appLockEnabled = false
                                    prefs.edit().putBoolean("app_lock_enabled", false).apply()
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
                        TextButton(onClick = { onExportCsv() }) {
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
                        Text("MAC vendor database: $macVendorDatabaseSize entries", fontSize = 12.sp, color = sheetSubtextColor)
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
        PrivacyScoreDetailSheet(
            devices = devices,
            currentTheme = currentTheme,
            calculatePrivacyScore = calculatePrivacyScore,
            onDismiss = { showPrivacyDetailSheet = false }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrivacyScoreDetailSheet(
    devices: List<DetectedDevice>,
    currentTheme: AppTheme,
    calculatePrivacyScore: () -> Int,
    onDismiss: () -> Unit
) {
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
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        // TASK 4: Show MAC address under device name for unknowns
                                        if (count == 1 && row.deviceType == DeviceType.UNKNOWN) {
                                            Column {
                                                Text(
                                                    row.deviceType.displayName,
                                                    style = MaterialTheme.typography.bodyMedium,
                                                    fontWeight = FontWeight.Medium
                                                )
                                                Text(
                                                    row.groupDevices.first().macAddress,
                                                    style = MaterialTheme.typography.bodySmall,
                                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                    fontFamily = FontFamily.Monospace,
                                                    fontSize = 11.sp
                                                )
                                            }
                                        } else {
                                            Text(
                                                if (count == 1) row.deviceType.displayName else "${count}x ${row.deviceType.displayName}",
                                                fontSize = 13.sp, color = textColor, fontWeight = FontWeight.Medium
                                            )
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
fun ScanModeButton(label: String, icon: ImageVector, selected: Boolean, onClick: () -> Unit) {
    val isDark = androidx.compose.foundation.isSystemInDarkTheme()
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
