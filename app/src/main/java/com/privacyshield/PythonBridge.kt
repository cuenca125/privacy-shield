package com.privacyshield

import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import android.content.Context
import org.json.JSONObject

object PythonBridge {

    private var initialized = false

    fun init(context: Context) {
        if (!initialized) {
            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(context))
            }
            initialized = true
        }
    }

    fun runHostScan(context: Context, target: String): NmapScanResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val result = if (RootFeatureGate.canUseRootFeatures()) {
                val module = py.getModule("nmap_scanner_root")
                module.callAttr("run_host_scan_nmap", target).toString()
            } else {
                val module = py.getModule("nmap_scanner")
                module.callAttr("run_host_scan", target).toString()
            }
            parseHostScanResult(result)
        } catch (e: Exception) {
            NmapScanResult(success = false, error = e.message ?: "Unknown error")
        }
    }

    fun runServiceScan(context: Context, target: String, ports: String = "22,80,443,8080,8443"): ServiceScanResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val result = if (RootFeatureGate.canUseRootFeatures()) {
                val module = py.getModule("nmap_scanner_root")
                module.callAttr("run_service_scan_nmap", target, ports).toString()
            } else {
                val module = py.getModule("nmap_scanner")
                module.callAttr("run_service_scan", target, ports).toString()
            }
            parseServiceScanResult(result, target)
        } catch (e: Exception) {
            ServiceScanResult(success = false, error = e.message ?: "Unknown error")
        }
    }

    private fun parseHostScanResult(json: String): NmapScanResult {
        val obj = JSONObject(json)
        return if (obj.getBoolean("success")) {
            val hosts = mutableListOf<NmapHost>()
            val arr = obj.getJSONArray("hosts")
            for (i in 0 until arr.length()) {
                val h = arr.getJSONObject(i)
                hosts.add(NmapHost(
                    ip = h.getString("ip"),
                    hostname = h.optString("hostname", ""),
                    state = h.optString("state", "unknown")
                ))
            }
            NmapScanResult(success = true, hosts = hosts)
        } else {
            NmapScanResult(success = false, error = obj.optString("error"))
        }
    }

    private fun parseServiceScanResult(json: String, host: String): ServiceScanResult {
        val obj = JSONObject(json)
        return if (obj.getBoolean("success")) {
            val services = mutableListOf<ServiceInfo>()
            val arr = obj.getJSONArray("services")
            for (i in 0 until arr.length()) {
                val s = arr.getJSONObject(i)
                services.add(ServiceInfo(
                    port = s.getInt("port"),
                    protocol = s.optString("protocol", "tcp"),
                    state = s.optString("state", "unknown"),
                    service = s.optString("service", ""),
                    version = s.optString("version", ""),
                    product = s.optString("product", "")
                ))
            }
            ServiceScanResult(success = true, host = obj.optString("host", host), services = services)
        } else {
            ServiceScanResult(success = false, error = obj.optString("error"))
        }
    }

    fun getInterfaceInfo(context: Context): String {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("scapy_inspector")
            module.callAttr("analyze_packet_info").toString()
        } catch (e: Exception) {
            """{"success": false, "error": "${e.message}"}"""
        }
    }

    fun isRootAvailable(context: Context): Boolean {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("scapy_inspector")
            module.callAttr("check_root_available").toBoolean()
        } catch (e: Exception) {
            false
        }
    }
}

data class NmapScanResult(val success: Boolean, val hosts: List<NmapHost> = emptyList(), val error: String? = null)
data class NmapHost(val ip: String, val hostname: String, val state: String)
data class ServiceScanResult(val success: Boolean, val host: String = "", val services: List<ServiceInfo> = emptyList(), val error: String? = null)
data class ServiceInfo(val port: Int, val protocol: String, val state: String, val service: String, val version: String, val product: String)
