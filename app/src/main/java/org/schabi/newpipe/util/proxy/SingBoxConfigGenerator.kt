package org.schabi.newpipe.util.proxy

import com.google.gson.GsonBuilder

object SingBoxConfigGenerator {

    fun generate(bean: StandardV2RayBean): String {
        val root = mutableMapOf<String, Any>()

        // 1. Log
        root["log"] = mapOf(
            "disabled" to false,
            "level" to "error",
            "timestamp" to true
        )

        // 2. DNS
        // Using a modernized DNS structure similar to reference, but simplified for single-proxy usage
        root["dns"] = mapOf(
            "servers" to listOf(
                mapOf("tag" to "dns_remote", "address" to "8.8.8.8", "detour" to "proxy"),
                mapOf("tag" to "dns_direct", "address" to "local", "detour" to "direct"),
                mapOf("tag" to "dns_block", "address" to "rcode://refused")
            ),
            "rules" to listOf(
                mapOf("outbound" to "any", "server" to "dns_direct"),
                mapOf("clash_mode" to "direct", "server" to "dns_direct"),
                mapOf("clash_mode" to "global", "server" to "dns_remote")
            ),
            "final" to "dns_remote",
            "strategy" to "prefer_ipv4",
            "independent_cache" to true
        )
        
        // 3. Inbounds
        // Match user reference port 7892
        root["inbounds"] = listOf(
            mapOf(
                "type" to "mixed",
                "tag" to "mixed-in",
                "listen" to "127.0.0.1",
                "listen_port" to 7892,
                "sniff" to true
            )
        )

        // 4. Outbounds
        val outbounds = mutableListOf<Map<String, Any>>()
        
        // Proxy Outbound (The active one)
        val proxyOutbound = buildOutbound(bean)
        // Ensure tag is "proxy" for routing reference
        val proxyMap = proxyOutbound.toMutableMap()
        proxyMap["tag"] = "proxy"
        outbounds.add(proxyMap)

        // Direct
        outbounds.add(mapOf("type" to "direct", "tag" to "direct"))
        // Block
        outbounds.add(mapOf("type" to "block", "tag" to "block"))
        // DNS Out
        outbounds.add(mapOf("type" to "dns", "tag" to "dns-out"))

        root["outbounds"] = outbounds

        // 5. Route
        root["route"] = mapOf(
            "rules" to listOf(
                mapOf("protocol" to "dns", "outbound" to "dns-out"),
                mapOf("inbound" to "mixed-in", "outbound" to "proxy"),
                // Add basic direct rules for local/private IPs to ensure safety
                mapOf("ip_cidr" to listOf("224.0.0.0/3", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"), "outbound" to "direct"),
                mapOf("domain_suffix" to listOf("cn"), "outbound" to "direct")
            ),
            "final" to "proxy",
            "auto_detect_interface" to true
        )
        
        // 6. Experimental
        root["experimental"] = mapOf(
             "cache_file" to mapOf("enabled" to true, "store_fakeip" to false)
        )

        return GsonBuilder().setPrettyPrinting().create().toJson(root)
    }

    private fun buildOutbound(bean: StandardV2RayBean): Map<String, Any> {
        val out = mutableMapOf<String, Any>()
        out["tag"] = "proxy"
        
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
