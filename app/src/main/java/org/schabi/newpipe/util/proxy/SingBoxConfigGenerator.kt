package org.schabi.newpipe.util.proxy

import com.google.gson.Gson
import com.google.gson.GsonBuilder

object SingBoxConfigGenerator {

    fun generate(bean: StandardV2RayBean): String {
        val root = mutableMapOf<String, Any>()

        // Log
        root["log"] = mapOf("level" to "info", "timestamp" to true)

        // DNS
        root["dns"] = mapOf(
            "servers" to listOf(
                mapOf("tag" to "google", "address" to "8.8.8.8", "detour" to "proxy"),
                mapOf("tag" to "local", "address" to "local", "detour" to "direct")
            ),
            "rules" to listOf(
                mapOf("outbound" to "any", "server" to "local")
            ),
            "final" to "local"
        )
        
        // Inbounds
        root["inbounds"] = listOf(
            mapOf(
                "type" to "mixed",
                "tag" to "mixed-in",
                "listen" to "127.0.0.1",
                "listen_port" to 10808,
                "sniff" to true
            )
        )

        // Outbounds
        val outbounds = mutableListOf<Map<String, Any>>()
        
        // Proxy Outbound
        val proxyOutbound = buildOutbound(bean)
        outbounds.add(proxyOutbound)

        // Direct/Block
        outbounds.add(mapOf("type" to "direct", "tag" to "direct"))
        outbounds.add(mapOf("type" to "block", "tag" to "block"))
        outbounds.add(mapOf("type" to "dns", "tag" to "dns-out"))

        root["outbounds"] = outbounds

        // Route
        root["route"] = mapOf(
            "rules" to listOf(
                mapOf("protocol" to "dns", "outbound" to "dns-out"),
                mapOf("inbound" to "mixed-in", "outbound" to "proxy")
            ),
            "auto_detect_interface" to true
        )
        
        // Experimental (for cache file)
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
