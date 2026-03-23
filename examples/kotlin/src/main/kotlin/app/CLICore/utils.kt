package app.CLICore

object Native {
    fun loadOrThrow() {
        System.loadLibrary("dkls")
    }
}

fun hexString(bytes: ByteArray): String {
    return bytes.joinToString("") { "%02x".format(it) }
}

fun hexToBytes(hex: String): ByteArray {
    val s = hex.trim().removePrefix("0x")
    require(s.length % 2 == 0) { "Hex length must be even" }
    return ByteArray(s.length / 2) { i ->
        s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}