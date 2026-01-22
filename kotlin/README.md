## References
- [UniFFI user guide on Kotlin - Integrating with Gradle](https://mozilla.github.io/uniffi-rs/latest/kotlin/gradle.html)
- [cargo-ndk - Build Rust code for Android](https://github.com/bbqsrc/cargo-ndk)
- [uniffi-starter - Android](https://github.com/ianthetechie/uniffi-starter/tree/main)
- [uniffi-starter - DeepWiki on Android Integration](https://deepwiki.com/ianthetechie/uniffi-starter/5-android-integration)

## Steps

### 1. Set up tools on your machine

- Install **Rust** with [`rustup`](https://rustup.rs/)
- Install Android Studio and create a new project.

#### 1.1. Android Project
- Install **Android NDK** via Android Studio (SDK Manager → SDK Tools → "NDK")
- Set `ANDROID_NDK_HOME` to your NDK path (Needed for `build-kotlin.sh`):
```
# For example:
export ANDROID_NDK_HOME=D:/Android/Sdk/ndk/29.0.14206865
```
- Install **cargo-ndk**, which is what compiles Rust code for Android:
```
cargo install cargo-ndk
```
- Add [Android Rust targets](https://github.com/bbqsrc/cargo-ndk?tab=readme-ov-file#installing) (these are the CPU/OS combos your .so will support):
```
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
```
- Install **uniffi** crate:
```
cargo install uniffi --features cli
```

#### 1.2. Kotlin CLI (Lightweight)
- Install **uniffi** crate:
```
cargo install uniffi --features cli
```
- Install JDK and ensure `java -version` works.
- Install **gradle** 9.3.0 (or newer):
```
sdk install gradle 9.3.0
```

### 2. Build the Kotlin Bindings for `dkls-wrapper`
- **\[OPTIONAL\]** Install [KTLint](https://pinterest.github.io/ktlint/latest/install/cli/) for formatting, or ignore the warnings during build
- Run `build-kotlin.sh` from the Repo's Root dir.
- You will see under `kotlin/` that the `src/main/java` and `src/main/jniLibs` are available, which you can then add as dependency for the Android App project. (End of documentation for Android App)
```
==> Building Rust shared library for host
    Finished `release` profile [optimized] target(s) in 0.15s
==> Copying native library into Kotlin resources
==> Cleaning old generated Kotlin bindings
==> Generating Kotlin bindings with uniffi-bindgen
Code generation complete, formatting with ktlint (use --no-format to disable)
==> Done
Kotlin bindings: kotlin/src/main/kotlin
Native library:  kotlin/src/main/resources/native
```

### 3. Running the Kotlin Program using Gradle
- Run `gradlew run` within your CLI, located within the `kotlin/`, to run the application.
