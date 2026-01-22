package app

import uniffi.dkls.*

object Native {
    fun loadOrThrow() {
        // Looks for "libdkls.so" (Linux) via java.library.path
        // e.g. run with: -Djava.library.path=kotlin/src/main/resources/native
        System.loadLibrary("dkls")
    }
}

fun main() {
    println("DKLS Kotlin CLI starting...")

    try {
        Native.loadOrThrow()
        println("Native library loaded: dkls")
    } catch (e: UnsatisfiedLinkError) {
        System.err.println("Failed to load native library 'dkls'.")
        System.err.println("Tip: run with -Djava.library.path=src/main/resources/native")
        throw e
    }

    // Minimal "binding is accessible" check:
    // Replace the line below with any trivial call/constant/type that exists in your generated dkls.kt.
    println("UniFFI bindings are on the classpath: ${Keyshare::class.qualifiedName}")

    println("Smoke test OK.")
}
