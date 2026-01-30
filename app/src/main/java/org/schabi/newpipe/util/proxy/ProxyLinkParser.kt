package org.schabi.newpipe.util.proxy

import com.google.gson.Gson
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import android.text.TextUtils
import android.util.Log

object ProxyLinkParser {

    private const val TAG = "ProxyLinkParser"

    fun parse(link: String): StandardV2RayBean? {
        return try {
            when {
                link.startsWith("vmess://") -> parseVMess(link)
                link.startsWith("vless://") -> parseVLESS(link)
                link.startsWith("trojan://") -> parseTrojan(link)
                else -> null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing link: $link", e)
            null
        }
    }

    private fun parseVMess(link: String): StandardV2RayBean {
        val result = ProxyUtils.decodeBase64UrlSafe(link.substringAfter("vmess://"))
        // Check if legacy format (not supported here for simplicity, assuming JSON)
        val vmessQRCode = Gson().fromJson(result, VmessQRCode::class.java)

        val bean = VMessBean()
        bean.name = vmessQRCode.ps
        bean.serverAddress = vmessQRCode.add
        bean.serverPort = vmessQRCode.port.toIntOrNull() ?: 443
        bean.encryption = vmessQRCode.scy
        bean.uuid = vmessQRCode.id
        bean.alterId = vmessQRCode.aid.toIntOrNull() ?: 0
        bean.type = vmessQRCode.net
        bean.host = vmessQRCode.host
        bean.path = vmessQRCode.path
        
        // Handle type adjustments
        val headerType = vmessQRCode.type
        if (bean.type == "tcp" && headerType == "http") {
             bean.type = "http"
        }

        // TLS settings
        if (vmessQRCode.tls == "tls" || vmessQRCode.tls == "reality") {
            bean.security = "tls"
            bean.sni = vmessQRCode.sni
            if (bean.sni.isEmpty()) bean.sni = bean.host
            bean.alpn = vmessQRCode.alpn
            bean.utlsFingerprint = vmessQRCode.fp
            
            if (vmessQRCode.tls == "reality") {
                // Reality fields not in standard v2rayN JSON usually? 
                // nb4a logic suggests reality might be handled if specific fields are present or checks link params
            }
        }
        
        return bean
    }

    private fun parseVLESS(link: String): StandardV2RayBean {
        val bean = VLESSBean()
        return parseUrl(link, bean)
    }

    private fun parseTrojan(link: String): StandardV2RayBean {
        val bean = TrojanBean()
        return parseUrl(link, bean)
    }

    private fun parseUrl(link: String, bean: StandardV2RayBean): StandardV2RayBean {
        val url = link.replace("vmess://", "https://") // Should not happen for vmess here
                      .replace("vless://", "https://")
                      .replace("trojan://", "https://")
                      .toHttpUrl()

        bean.serverAddress = url.host
        bean.serverPort = url.port
        bean.name = url.fragment ?: ""
        
        // Credentials
        if (bean is TrojanBean) {
            bean.password = url.username
        } else {
            bean.uuid = url.username
        }

        // Params
        bean.type = url.queryParameter("type") ?: "tcp"
        val securityParam = url.queryParameter("security")
        bean.security = if (securityParam.isNullOrEmpty()) {
             if (bean is TrojanBean) "tls" else "none"
        } else {
            securityParam
        }

        // Common settings
        if (bean.security == "tls" || bean.security == "reality") {
             bean.security = "tls" // Sing-box uses 'tls' with reality options
             bean.allowInsecure = url.queryParameter("allowInsecure") == "1" || url.queryParameter("allowInsecure") == "true"
             bean.sni = url.queryParameter("sni") ?: ""
             if (bean.sni.isEmpty()) bean.sni = url.queryParameter("host") ?: ""
             bean.alpn = url.queryParameter("alpn") ?: ""
             bean.utlsFingerprint = url.queryParameter("fp") ?: ""
             
             val pbk = url.queryParameter("pbk")
             if (!pbk.isNullOrEmpty()) {
                 bean.realityPubKey = pbk
                 bean.realityShortId = url.queryParameter("sid") ?: ""
             }
        }

        url.queryParameter("flow")?.let {
             if (bean.isVLESS) bean.encryption = it
        }

        // Transport
        when (bean.type) {
            "ws" -> {
                bean.host = url.queryParameter("host") ?: ""
                bean.path = url.queryParameter("path") ?: ""
            }
            "http" -> {
                 bean.host = url.queryParameter("host") ?: ""
                 bean.path = url.queryParameter("path") ?: ""
            }
            "grpc" -> {
                 bean.path = url.queryParameter("serviceName") ?: ""
            }
        }

        return bean
    }
}
