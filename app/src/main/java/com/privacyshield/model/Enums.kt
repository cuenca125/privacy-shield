package com.privacyshield.model

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.ui.graphics.vector.ImageVector

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

enum class AppTheme { LIGHT, DARK }
enum class ScanMode { FULL, CAMERAS_ONLY, MICS_ONLY }
enum class AppTab { HOME, SEARCH, NETWORK, TOOLS, SECURITY }
