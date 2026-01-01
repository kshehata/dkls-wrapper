## References
- [UniFFI user guide on Kotlin - Integrating with Gradle](https://mozilla.github.io/uniffi-rs/latest/kotlin/gradle.html)
- [cargo-ndk - Build Rust code for Android](https://github.com/bbqsrc/cargo-ndk)
- [uniffi-starter - Android](https://github.com/ianthetechie/uniffi-starter/tree/main)
- [uniffi-starter - DeepWiki on Android Integration](https://deepwiki.com/ianthetechie/uniffi-starter/5-android-integration)

## Steps

### 1. Set up tools on your machine

- Install **Rust** with [`rustup`](https://rustup.rs/)
- Install Android Studio and create a new project.
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

### 2. Build the Kotlin Bindings for `dkls-wrapper`
- Run `build-kotlin.sh` from the Repo's Root dir.
- You will see under `kotlin/` that the `src/main/java` and `src/main/jniLibs` are available, which you can then add as dependency for the Android App project.
```
==> Done.
Kotlin bindings generated into: kotlin/src/main/java
Android .so libraries generated into: kotlin/src/main/jniLibs

Next steps:
  - Add the kotlin module as a dependency of your app.
  - Call System.loadLibrary("dkls") before using the generated Kotlin classes.
```
