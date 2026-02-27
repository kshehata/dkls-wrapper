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
### 3. Setting up the MQTT Broker
This project’s Kotlin CLIs expect an MQTT broker reachable at `host:port` (default `localhost:1883`).
#### For this segment, we'll look into local Terminal setup ONLY
- Go-to [Eclipse Mosquitto](https://mosquitto.org/) for Windows download.
- Run the `.exe` file, and install accordingly.
- After installation finishes, the Broker *SHOULD* be accessible.
- On Windows, you can check if the port is opened according with the following:
```
tnc localhost -Port 1883
```

### 4. Running the Kotlin Programs (CLI) using Gradle
#### What you need
- Access to an [MQTT broker](https://mosquitto.org/) (default `localhost:1883`) mentioned in Step 3.
#### How to use
- Go into the Kotlin CLI directory (the folder that contains `build.gradle.kts`).
```
cd kotlin
```
- Run the DKG key generation CLI with Gradle:
```
./gradlew keygen
```
- Enter the necessary information when prompted.
- To start a new DKG (the first device):
   - Leave the QR data input empty.
   - The program will print “My QR” as a Base64 string. Copy this QR string and share it with the other devices that should join the same DKG session.
- To join an existing DKG (another device):
   - Paste the Base64 “My QR” string from the first device into the QR data prompt.
   - The program will automatically use the instance ID from the QR data to derive the correct MQTT topics for setup/protocol messaging.
- While the program is running:
   - Paste additional devices’ QR data (Base64) into the terminal to mark them as "Verified" in the setup.
   - When the node reaches the `READY` state, press Enter on an empty line to start the DKG.
- After the DKG completes:
   - The program writes the device’s local data to the output filename you chose (default `keyshare_<name>`).

### 5. Running the Signing Program using Gradle
#### What you need
- A keyshare/ device local data file produced by the DKG CLI (CLIKeyGen), since CLISign loads `DeviceLocalData` from that file at startup.
- Access to an [MQTT broker](https://mosquitto.org/) (default `localhost:1883`) mentioned in Step 3.
#### How to get started
- Go into/Remain in the Kotlin CLI directory (the folder that contains `build.gradle.kts`).
```
cd kotlin
```
- Run the signing CLI with Gradle:
```
./gradlew sign
```
- When the program starts, it asks for:
  - Keyshare filename (required).
  - Message to sign (optional; empty = listener mode).
  - Skip confirmation for signing requests (enter `y` to auto-approve requests - **Highly recommended for ease of use**).
  - MQTT host (defaults to `localhost`).
  - MQTT port (defaults to `1883`).

#### Using the interactive commands
- After startup, CLISign enters a simple command loop.
- Available Commands:
  - `s <message>`: Request a signature for a string message (outgoing request).
  - `a <index>`: Approve a pending incoming request by index.
  - `c <index>`: Cancel a request by index.
  - `l`: List pending incoming requests.
  - `v <message> <sigHex>`: Verify a signature against a string message (Caps Sensitive) via group verifying key from your keyshare.
  - `x`: Exit.
