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

    fun runDeepScan(context: Context, target: String, arguments: String): DeepScanResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("nmap_scanner_root")
            val json = module.callAttr("run_deep_scan", target, arguments).toString()
            parseDeepScanResult(json)
        } catch (e: Exception) {
            DeepScanResult(success = false, error = e.message ?: "Unknown error")
        }
    }

    fun runArpScan(context: Context, network: String): ArpScanResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("scapy_inspector")
            val json = module.callAttr("arp_scan", network).toString()
            parseArpScanResult(json)
        } catch (e: Exception) {
            ArpScanResult(success = false, error = e.message ?: "Unknown error")
        }
    }

    fun detectArpSpoofing(context: Context, interfaceName: String, duration: Int = 10): ArpSpoofResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("scapy_inspector")
            val json = module.callAttr("detect_arp_spoofing", interfaceName, duration).toString()
            parseArpSpoofResult(json)
        } catch (e: Exception) {
            ArpSpoofResult(success = false, error = e.message ?: "Unknown error")
        }
    }

    fun captureTrafficSummary(context: Context, interfaceName: String, duration: Int = 5): TrafficSummaryResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("scapy_inspector")
            val json = module.callAttr("capture_traffic_summary", interfaceName, duration).toString()
            parseTrafficResult(json)
        } catch (e: Exception) {
            TrafficSummaryResult(success = false, error = e.message ?: "Unknown error")
        }
    }

    fun runCustomScript(context: Context, script: String): ScriptResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("scapy_inspector")
            val json = module.callAttr("run_custom_script", script).toString()
            val obj = JSONObject(json)
            ScriptResult(
                success = obj.getBoolean("success"),
                output = obj.optString("output", ""),
                errors = obj.optString("errors", "")
            )
        } catch (e: Exception) {
            ScriptResult(success = false, errors = e.message ?: "Unknown error")
        }
    }

    fun checkMonitorMode(context: Context, interfaceName: String): MonitorModeResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("scapy_inspector")
            val json = module.callAttr("check_monitor_mode", interfaceName).toString()
            val obj = JSONObject(json)
            MonitorModeResult(
                success = obj.getBoolean("success"),
                isMonitor = obj.optBoolean("monitor_mode", false),
                output = obj.optString("output", "")
            )
        } catch (e: Exception) {
            MonitorModeResult(success = false, error = e.message)
        }
    }

    fun probeForEvilTwin(context: Context, ssid: String, interfaceName: String = "wlan0"): EvilTwinProbeResult {
        init(context)
        return try {
            val py = Python.getInstance()
            val module = py.getModule("scapy_inspector")
            val json = module.callAttr("probe_for_evil_twin", ssid, interfaceName).toString()
            parseEvilTwinProbeResult(json)
        } catch (e: Exception) {
            EvilTwinProbeResult(success = false, error = e.message)
        }
    }

    private fun parseDeepScanResult(json: String): DeepScanResult {
        val obj = JSONObject(json)
        if (!obj.getBoolean("success")) return DeepScanResult(success = false, error = obj.optString("error"))
        val hosts = mutableListOf<DeepScanHost>()
        val arr = obj.getJSONArray("results")
        for (i in 0 until arr.length()) {
            val h = arr.getJSONObject(i)
            val osList = mutableListOf<OsMatch>()
            val osArr = h.optJSONArray("os")
            if (osArr != null) {
                for (j in 0 until osArr.length()) {
                    val o = osArr.getJSONObject(j)
                    osList.add(OsMatch(o.getString("name"), o.getString("accuracy")))
                }
            }
            val ports = mutableListOf<DeepPort>()
            val portArr = h.optJSONArray("ports")
            if (portArr != null) {
                for (j in 0 until portArr.length()) {
                    val p = portArr.getJSONObject(j)
                    ports.add(DeepPort(
                        port = p.getInt("port"),
                        protocol = p.optString("protocol", "tcp"),
                        state = p.optString("state", ""),
                        service = p.optString("service", ""),
                        version = p.optString("version", ""),
                        product = p.optString("product", "")
                    ))
                }
            }
            hosts.add(DeepScanHost(
                ip = h.getString("ip"),
                hostname = h.optString("hostname", ""),
                state = h.optString("state", ""),
                os = osList,
                ports = ports
            ))
        }
        return DeepScanResult(success = true, hosts = hosts)
    }

    private fun parseArpScanResult(json: String): ArpScanResult {
        val obj = JSONObject(json)
        if (!obj.getBoolean("success")) return ArpScanResult(success = false, error = obj.optString("error"))
        val hosts = mutableListOf<ArpHost>()
        val arr = obj.getJSONArray("hosts")
        for (i in 0 until arr.length()) {
            val h = arr.getJSONObject(i)
            hosts.add(ArpHost(ip = h.getString("ip"), mac = h.getString("mac")))
        }
        return ArpScanResult(success = true, hosts = hosts)
    }

    private fun parseArpSpoofResult(json: String): ArpSpoofResult {
        val obj = JSONObject(json)
        if (!obj.getBoolean("success")) return ArpSpoofResult(success = false, error = obj.optString("error"))
        val anomalies = mutableListOf<ArpAnomaly>()
        val arr = obj.getJSONArray("anomalies")
        for (i in 0 until arr.length()) {
            val a = arr.getJSONObject(i)
            anomalies.add(ArpAnomaly(
                ip = a.getString("ip"),
                oldMac = a.getString("old_mac"),
                newMac = a.getString("new_mac"),
                timestamp = a.getString("timestamp")
            ))
        }
        return ArpSpoofResult(
            success = true,
            anomalies = anomalies,
            hostsSeen = obj.optInt("hosts_seen", 0)
        )
    }

    private fun parseTrafficResult(json: String): TrafficSummaryResult {
        val obj = JSONObject(json)
        if (!obj.getBoolean("success")) return TrafficSummaryResult(success = false, error = obj.optString("error"))
        val protocolsObj = obj.optJSONObject("protocols")
        val protocols = mutableMapOf<String, Int>()
        if (protocolsObj != null) {
            for (key in protocolsObj.keys()) {
                protocols[key] = protocolsObj.getInt(key)
            }
        }
        val recentPackets = mutableListOf<PacketEntry>()
        val arr = obj.optJSONArray("recent_packets")
        if (arr != null) {
            for (i in 0 until arr.length()) {
                val p = arr.getJSONObject(i)
                recentPackets.add(PacketEntry(
                    src = p.getString("src"),
                    dst = p.getString("dst"),
                    protocol = p.getString("protocol"),
                    size = p.getInt("size"),
                    time = p.getString("time")
                ))
            }
        }
        return TrafficSummaryResult(
            success = true,
            packetCount = obj.optInt("packet_count", 0),
            uniqueIps = obj.optInt("unique_ips", 0),
            protocols = protocols,
            recentPackets = recentPackets
        )
    }

    private fun parseEvilTwinProbeResult(json: String): EvilTwinProbeResult {
        val obj = JSONObject(json)
        if (!obj.getBoolean("success")) return EvilTwinProbeResult(success = false, error = obj.optString("error"))
        val responses = mutableListOf<ProbeResponse>()
        val arr = obj.getJSONArray("responses")
        for (i in 0 until arr.length()) {
            val r = arr.getJSONObject(i)
            responses.add(ProbeResponse(
                bssid = r.getString("bssid"),
                ssid = r.getString("ssid"),
                signal = r.optInt("signal", 0)
            ))
        }
        return EvilTwinProbeResult(
            success = true,
            responses = responses,
            evilTwinSuspected = obj.optBoolean("evil_twin_suspected", false),
            ssid = obj.optString("ssid", "")
        )
    }
}

data class NmapScanResult(val success: Boolean, val hosts: List<NmapHost> = emptyList(), val error: String? = null)
data class NmapHost(val ip: String, val hostname: String, val state: String)
data class ServiceScanResult(val success: Boolean, val host: String = "", val services: List<ServiceInfo> = emptyList(), val error: String? = null)
data class ServiceInfo(val port: Int, val protocol: String, val state: String, val service: String, val version: String, val product: String)
data class DeepScanHost(val ip: String, val hostname: String, val state: String, val os: List<OsMatch> = emptyList(), val ports: List<DeepPort> = emptyList())
data class OsMatch(val name: String, val accuracy: String)
data class DeepPort(val port: Int, val protocol: String, val state: String, val service: String, val version: String, val product: String)
data class DeepScanResult(val success: Boolean, val hosts: List<DeepScanHost> = emptyList(), val error: String? = null)
data class ArpHost(val ip: String, val mac: String)
data class ArpScanResult(val success: Boolean, val hosts: List<ArpHost> = emptyList(), val error: String? = null)
data class ArpAnomaly(val ip: String, val oldMac: String, val newMac: String, val timestamp: String)
data class ArpSpoofResult(val success: Boolean, val anomalies: List<ArpAnomaly> = emptyList(), val hostsSeen: Int = 0, val error: String? = null)
data class PacketEntry(val src: String, val dst: String, val protocol: String, val size: Int, val time: String)
data class TrafficSummaryResult(val success: Boolean, val packetCount: Int = 0, val uniqueIps: Int = 0, val protocols: Map<String, Int> = emptyMap(), val recentPackets: List<PacketEntry> = emptyList(), val error: String? = null)
data class MonitorModeResult(val success: Boolean, val isMonitor: Boolean = false, val output: String = "", val error: String? = null)
data class ProbeResponse(val bssid: String, val ssid: String, val signal: Int)
data class EvilTwinProbeResult(val success: Boolean, val responses: List<ProbeResponse> = emptyList(), val evilTwinSuspected: Boolean = false, val ssid: String = "", val error: String? = null)
data class ScriptResult(val success: Boolean, val output: String = "", val errors: String = "")
