import org.gradle.api.tasks.JavaExec
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.3.0"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.12.0")  // JNA library (refer to `https://mozilla.github.io/uniffi-rs/latest/kotlin/gradle.html#jna-dependency`)
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")  // Kotlin coroutines library (refer to `https://github.com/Kotlin/kotlinx.coroutines`)
    testImplementation(kotlin("test"))  // Kotlin's test library (refer to `https://kotlinlang.org/docs/gradle-configure-project.html#set-dependencies-on-test-libraries`)

    // KMqtt library (refer to `https://github.com/davidepianca98/KMQTT/tree/1.0.0`)
    implementation("io.github.davidepianca98:kmqtt-common-jvm:1.0.0")
    implementation("io.github.davidepianca98:kmqtt-client-jvm:1.0.0")
}

kotlin {
    // Baseline toolchain: compile using JDK 17
    jvmToolchain(17)
}

// Baseline bytecode: produce artifacts runnable on Java 17+
tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

application {
    mainClass.set("app.MainKt")  // Such that `app/Main.kt` contains `main()`
}

val nativeDir = layout.projectDirectory.dir("src/main/resources/native").asFile.absolutePath

tasks.named<JavaExec>("run") {
    systemProperty("java.library.path", nativeDir)
    workingDir = project.projectDir  // Make runs consistent even if launched from elsewhere
}

tasks.test {
    useJUnitPlatform()  // JUnitPlatform for tests. See `https://docs.gradle.org/current/javadoc/org/gradle/api/tasks/testing/Test.html#useJUnitPlatform`
}