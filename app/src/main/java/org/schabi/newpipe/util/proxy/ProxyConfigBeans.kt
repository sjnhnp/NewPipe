package org.schabi.newpipe.util.proxy

import com.google.gson.annotations.SerializedName

open class StandardV2RayBean {
    var name: String = ""
    var serverAddress: String = ""
    var serverPort: Int = 0
    var type: String = "tcp" // tcp, ws, grpc, http, etc.
    var uuid: String = "" // or password
    var alterId: Int = 0
    var security: String = "auto" // auto, none, zero, aes-128-gcm, etc.

    // VMess specific
    var encryption: String = "auto"

    // TLS / Stream settings
    var sni: String = ""
    var alpn: String = ""
    var host: String = ""
    var path: String = ""
    var allowInsecure: Boolean = false
    var utlsFingerprint: String = ""
    
    // Reality
    var realityPubKey: String = ""
    var realityShortId: String = ""
    
    // WS
    var wsMaxEarlyData: Int = 0
    var earlyDataHeaderName: String = ""

    // Trojan
    var password: String = ""

    var isVLESS: Boolean = false
    
    // Packet Encoding
    var packetEncoding: Int = 0 
}

class VMessBean : StandardV2RayBean()
class VLESSBean : StandardV2RayBean() {
    init {
        isVLESS = true
    }
}
class TrojanBean : StandardV2RayBean()

data class VmessQRCode(
    var v: String = "",
    var ps: String = "",
    var add: String = "",
    var port: String = "",
    var id: String = "",
    var aid: String = "0",
    var scy: String = "",
    var net: String = "",
    var type: String = "",
    var host: String = "",
    var path: String = "",
    var tls: String = "",
    var sni: String = "",
    var alpn: String = "",
    var fp: String = "",
)
