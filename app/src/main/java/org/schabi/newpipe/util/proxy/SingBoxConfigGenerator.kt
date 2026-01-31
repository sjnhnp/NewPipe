package org.schabi.newpipe.util.proxy

import com.google.gson.GsonBuilder

object SingBoxConfigGenerator {

    fun generate(bean: StandardV2RayBean): String {
        val root = mutableMapOf<String, Any>()

        // 1. Log
        root["log"] = mapOf(
            "disabled" to true,
            "level" to "error",
            "timestamp" to true
        )

        // 2. DNS
        // 1.12.0+ Spec: Use "type" + "server", deprecate "address"
        root["dns"] = mapOf(
            "servers" to listOf(
                mapOf(
                    "tag" to "dns_direct",
                    "type" to "quic", 
                    "server" to "223.5.5.5",
                    "detour" to "DIRECT"
                ),
                mapOf(
                    "tag" to "dns_fakeip",
                    "type" to "fakeip",
                    "inet4_range" to "198.18.0.0/15"
                )
            ),
            "final" to "dns_fakeip",
            "strategy" to "prefer_ipv4",
            "independent_cache" to true,
            "reverse_mapping" to true
        )
        
        // 3. Inbounds
        // 1.12.0+ Spec: Remove "sniff" field (moved to route action)
        root["inbounds"] = listOf(
            mapOf(
                "type" to "mixed",
                "tag" to "mixed-in",
                "listen" to "127.0.0.1",
                "listen_port" to 7892
            )
        )

        // 4. Outbounds
        // 1.12.0+ Spec: Remove "block" and "dns" types
        val outbounds = mutableListOf<Map<String, Any>>()
        
        // Main Proxy Outbound
        val proxyOutbound = buildOutbound(bean)
        val proxyMap = proxyOutbound.toMutableMap()
        proxyMap["tag"] = "PROXY"
        outbounds.add(proxyMap)

        // Direct Outbound
        outbounds.add(mapOf("type" to "direct", "tag" to "DIRECT"))

        root["outbounds"] = outbounds

        // 5. Route
        root["route"] = mapOf(
            "default_domain_resolver" to "dns_direct",
            "rules" to listOf(
                // Action: Sniff (Migrated from inbound.sniff)
                mapOf("inbound" to "mixed-in", "action" to "sniff", "timeout" to "300ms"),
                
                // Action: Hijack DNS (Standard intercept)
                mapOf("port" to 53, "action" to "hijack-dns"),
                
                // Traffic Routing: App -> PROXY
                mapOf("inbound" to "mixed-in", "outbound" to "PROXY"),
                
                // Safety net: Private IPs -> DIRECT
                mapOf("ip_cidr" to listOf("224.0.0.0/3", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"), "outbound" to "DIRECT")
            ),
            "final" to "PROXY",
            "auto_detect_interface" to true
        )
        
        // 6. Experimental
        root["experimental"] = mapOf(
             "cache_file" to mapOf("enabled" to true, "store_fakeip" to true)
        )

        return GsonBuilder().setPrettyPrinting().create().toJson(root)
    }

    private fun buildOutbound(bean: StandardV2RayBean): Map<String, Any> {
        val out = mutableMapOf<String, Any>()
        out["tag"] = "PROXY"
        
        out["server"] = bean.serverAddress
        out["server_port"] = bean.serverPort

        // Stream Settings (Transport)
        val transport = mutableMapOf<String, Any>()
        when (bean.type) {
            "ws" -> {
                transport["type"] = "ws"
                transport["path"] = if (bean.path.isNotEmpty()) bean.path else "/"
                if (bean.host.isNotEmpty()) {
                    transport["headers"] = mapOf("Host" to bean.host)
                }
                if (bean.wsMaxEarlyData > 0) {
                    transport["max_early_data"] = bean.wsMaxEarlyData
                    transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
                }
            }
            "http" -> {
                transport["type"] = "http"
                transport["path"] = if (bean.path.isNotEmpty()) bean.path else "/"
                if (bean.host.isNotEmpty()) {
                    transport["host"] = bean.host.split(",")
                }
            }
            "grpc" -> {
                transport["type"] = "grpc"
                transport["service_name"] = bean.path
            }
            "quic" -> transport["type"] = "quic"
        }
        if (transport.isNotEmpty()) {
            out["transport"] = transport
        }

        // TLS
        if (bean.security == "tls") {
             val tls = mutableMapOf<String, Any>()
             tls["enabled"] = true
             tls["insecure"] = bean.allowInsecure
             if (bean.sni.isNotEmpty()) tls["server_name"] = bean.sni
             if (bean.alpn.isNotEmpty()) tls["alpn"] = bean.alpn.split(",")
             if (bean.utlsFingerprint.isNotEmpty()) {
                 tls["utls"] = mapOf("enabled" to true, "fingerprint" to bean.utlsFingerprint)
             }
             
             if (bean.realityPubKey.isNotEmpty()) {
                 tls["reality"] = mapOf(
                     "enabled" to true,
                     "public_key" to bean.realityPubKey,
                     "short_id" to bean.realityShortId
                 )
             }
             out["tls"] = tls
        }

        // Protocol Specifics
        when {
            bean is VLESSBean || (bean is VMessBean && bean.isVLESS) -> {
                out["type"] = "vless"
                out["uuid"] = bean.uuid
                if (bean.encryption.isNotEmpty() && bean.encryption != "auto") {
                    out["flow"] = bean.encryption
                }
                // packet encoding
            }
            bean is VMessBean -> {
                out["type"] = "vmess"
                out["uuid"] = bean.uuid
                out["alter_id"] = bean.alterId
                out["security"] = if (bean.encryption.isNotEmpty()) bean.encryption else "auto"
                // packet encoding
            }
            bean is TrojanBean -> {
                out["type"] = "trojan"
                out["password"] = bean.password
            }
        }

        return out
    }
}
