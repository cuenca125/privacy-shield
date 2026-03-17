package com.privacyshield.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.privacyshield.model.AppTab
import com.privacyshield.model.AppTheme

@Composable
fun BottomNavigationBar(
    currentTab: AppTab,
    currentTheme: AppTheme,
    nmapLoading: Boolean,
    serviceLoading: Boolean,
    selectedDevice: Any?,
    onTabSelected: (AppTab) -> Unit,
    onHomeReset: () -> Unit,
    onSearchReset: () -> Unit,
    onNetworkReset: () -> Unit,
    onSecurityReset: () -> Unit,
    onSelectedDeviceClear: () -> Unit
) {
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
                                    onSelectedDeviceClear()
                                } else {
                                    onHomeReset()
                                }
                            }
                            AppTab.SEARCH -> onSearchReset()
                            AppTab.NETWORK -> onNetworkReset()
                            AppTab.SECURITY -> onSecurityReset()
                            AppTab.TOOLS -> { /* no reset for tools */ }
                        }
                    } else {
                        onTabSelected(tab)
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
