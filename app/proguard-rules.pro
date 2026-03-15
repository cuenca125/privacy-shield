# Chaquopy
-keep class com.chaquo.python.** { *; }
-dontwarn com.chaquo.python.**

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-dontwarn androidx.room.**

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-dontwarn kotlinx.coroutines.**

# OkHttp / networking
-dontwarn okhttp3.**
-dontwarn okio.**

# Keep data classes used in JSON parsing
-keep class com.privacyshield.CveResult { *; }
-keep class com.privacyshield.NmapScanResult { *; }
-keep class com.privacyshield.NmapHost { *; }
-keep class com.privacyshield.ServiceScanResult { *; }
-keep class com.privacyshield.ServiceInfo { *; }
-keep class com.privacyshield.EvilTwinAlert { *; }
-keep class com.privacyshield.TraceHop { *; }

# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile