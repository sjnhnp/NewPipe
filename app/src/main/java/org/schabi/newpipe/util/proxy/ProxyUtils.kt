package org.schabi.newpipe.util.proxy

import android.util.Base64

object ProxyUtils {
    fun decodeBase64UrlSafe(str: String): String {
        var result = str.trim()
        if (result.isBlank()) return ""
        // Replace URL-safe chars with standard if mostly URL-safe
        result = result.replace("-", "+").replace("_", "/")
        // Fix padding
        val padding = 4 - (result.length % 4)
        if (padding < 4) {
            result += "=".repeat(padding)
        }
        return try {
            String(Base64.decode(result, Base64.DEFAULT), Charsets.UTF_8)
        } catch (e: Exception) {
            String(Base64.decode(result, Base64.NO_WRAP), Charsets.UTF_8)
        }
    }
}
