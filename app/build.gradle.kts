import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
    alias(libs.plugins.kotlin.android)
    id("com.chaquo.python") version "16.0.0"
}

android {
    namespace = "com.privacyshield"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.privacyshield"
        minSdk = 24
        targetSdk = 34
        versionCode = 3
        versionName = "1.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("boolean", "ENABLE_ROOT_FEATURES", "false")
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
            debugSymbolLevel = "FULL"
        }
    }

    chaquopy {
        defaultConfig {
            version = "3.11"
            pip {
                install("python-nmap")
                install("scapy")
            }
        }
    }

    // SECURITY FIX: Load keystore credentials from keystore.properties or environment variables.
    // Hardcoded fallback passwords removed. Signing is skipped if neither source provides credentials.
    signingConfigs {
        create("release") {
            val keystorePropsFile = rootProject.file("keystore.properties")
            val envKeystorePath = System.getenv("KEYSTORE_PATH")
            val envPassword = System.getenv("KEYSTORE_PASSWORD")
            val envAlias = System.getenv("KEY_ALIAS")
            val envKeyPassword = System.getenv("KEY_PASSWORD")

            if (envKeystorePath != null && envPassword != null && envAlias != null && envKeyPassword != null) {
                // CI/CD path: all credentials from environment variables
                val keystoreFile = file(envKeystorePath)
                if (keystoreFile.exists()) {
                    storeFile = keystoreFile
                    storePassword = envPassword
                    keyAlias = envAlias
                    keyPassword = envKeyPassword
                }
            } else if (keystorePropsFile.exists()) {
                // Local development path: credentials from keystore.properties (not committed to VCS)
                val keystoreProps = Properties().also { props ->
                    keystorePropsFile.inputStream().use { stream -> props.load(stream) }
                }
                val localKeystorePath = keystoreProps.getProperty("storeFile") ?: "keystore/release.keystore"
                val keystoreFile = file(localKeystorePath)
                if (keystoreFile.exists()) {
                    storeFile = keystoreFile
                    storePassword = keystoreProps.getProperty("storePassword")
                    keyAlias = keystoreProps.getProperty("keyAlias")
                    keyPassword = keystoreProps.getProperty("keyPassword")
                }
            }
            // If neither source is available, signing is skipped (unsigned APK produced)
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    lint {
        abortOnError = false
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.material:material-icons-extended")
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation("androidx.work:work-runtime-ktx:2.9.0")
    implementation("androidx.biometric:biometric:1.1.0")
}