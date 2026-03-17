package com.privacyshield.ui

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
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.privacyshield.model.AppTab
import com.privacyshield.model.AppTheme
import com.privacyshield.model.DetectedDevice
import com.privacyshield.model.DeviceType
import kotlinx.coroutines.launch

@Composable
fun SearchTab(
    devices: List<DetectedDevice>,
    currentTheme: AppTheme,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    selectedFilter: DeviceType?,
    onSelectedFilterChange: (DeviceType?) -> Unit,
    searchSortOption: Int,
    onSearchSortOptionChange: (Int) -> Unit,
    searchSuspiciousOnly: Boolean,
    onSearchSuspiciousOnlyChange: (Boolean) -> Unit,
    searchSafeOnly: Boolean,
    onSearchSafeOnlyChange: (Boolean) -> Unit,
    searchResetTrigger: Int,
    searchScrollTrigger: Int,
    onDeviceSelected: (DetectedDevice) -> Unit,
    onTabChange: (AppTab) -> Unit,
    getDeviceColor: (DeviceType) -> Color
) {
    val bgColor = if (currentTheme == AppTheme.DARK) Color(0xFF000000) else Color(0xFFF5F5F5)
    val cardColor = if (currentTheme == AppTheme.DARK) Color(0xFF1A1A1A) else Color.White
    val textColor = if (currentTheme == AppTheme.DARK) Color.White else Color.Black
    val subtextColor = if (currentTheme == AppTheme.DARK) Color(0xFF666666) else Color(0xFF888888)

    var showSortMenu by remember { mutableStateOf(false) }
    val searchListState = rememberLazyListState()
    val searchScope = rememberCoroutineScope()
    LaunchedEffect(searchResetTrigger) {
        if (searchResetTrigger > 0) {
            onSearchQueryChange("")
            onSelectedFilterChange(null)
            onSearchSortOptionChange(0)
            onSearchSuspiciousOnlyChange(false)
            onSearchSafeOnlyChange(false)
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
            onValueChange = { onSearchQueryChange(it) },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("Search by name, MAC, or manufacturer...",
                color = subtextColor, fontSize = 14.sp) },
            leadingIcon = { Icon(Icons.Filled.Search, null, tint = subtextColor) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { onSearchQueryChange("") }) {
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
                IconButton(onClick = { onSearchSuspiciousOnlyChange(!searchSuspiciousOnly); onSearchSafeOnlyChange(false) },
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
                                onClick = { onSearchSortOptionChange(i); showSortMenu = false }
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
                    onClick = { onSelectedFilterChange(null) },
                    label = { Text("All (${devices.size})") }
                )
            }
            DeviceType.values().forEach { type ->
                val count = devices.count { it.type == type }
                if (count > 0) {
                    item {
                        FilterChip(
                            selected = selectedFilter == type,
                            onClick = { onSelectedFilterChange(if (selectedFilter == type) null else type) },
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
                    DeviceCard(
                        device = device,
                        cardColor = cardColor,
                        textColor = textColor,
                        subtextColor = subtextColor,
                        accentColor = getDeviceColor(device.type),
                        onDeviceSelected = onDeviceSelected,
                        onTabChange = onTabChange
                    )
                }
            }
        }
    }
}

@Composable
fun DeviceCard(
    device: DetectedDevice,
    cardColor: Color,
    textColor: Color,
    subtextColor: Color,
    accentColor: Color? = null,
    onDeviceSelected: (DetectedDevice) -> Unit,
    onTabChange: (AppTab) -> Unit
) {
    val currentThemeIsDark = cardColor == Color(0xFF1A1A1A)
    val showWarning = device.isSuspicious() && device.isVeryClose()
    val backgroundColor = when {
        showWarning -> if (currentThemeIsDark) Color(0xFF3A1A1A) else Color(0xFFFFE5E5)
        device.isSuspicious() -> if (currentThemeIsDark) Color(0xFF2A1A1A) else Color(0xFFFFF5F5)
        else -> cardColor
    }

    val signalColor = getSignalColorStatic(device.signalStrength)
    val distanceColor = getDistanceColorStatic(device.getDistance())

    Card(
        modifier = Modifier.fillMaxWidth().clickable {
            onDeviceSelected(device)
            onTabChange(AppTab.HOME)
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
                    Icon(device.type.icon, null, tint = accentColor ?: subtextColor, modifier = Modifier.size(32.dp))
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
                            color = distanceColor, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }

                Column(horizontalAlignment = Alignment.End) {
                    Text("${device.signalStrength} dBm", color = signalColor,
                        fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    if (device.protocol.isNotEmpty()) {
                        Text(device.protocol, color = subtextColor, fontSize = 10.sp)
                    }
                    if (showWarning) {
                        Text("\u26a0\ufe0f", fontSize = 16.sp)
                    }
                }
            }
        }
    }
}

fun getSignalColorStatic(signal: Int): Color = when {
    signal > -50 -> Color(0xFF44FF88)
    signal > -60 -> Color(0xFF88FF44)
    signal > -70 -> Color(0xFFFFAA44)
    else -> Color(0xFFFF4444)
}

fun getDistanceColorStatic(distance: Double): Color = when {
    distance < 5 -> Color(0xFFFF4444)
    distance < 15 -> Color(0xFFFFAA44)
    else -> Color(0xFF44FF88)
}
