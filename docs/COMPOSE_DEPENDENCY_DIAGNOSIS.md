# Compose Dependency Configuration

## Repository: D:\ARM (ARM Digital Safety Guardian)

## 1. Dependency Configuration

| Component | Version |
|-----------|---------|
| AGP | 8.6.0 |
| Kotlin | 2.0.0 (with the `org.jetbrains.kotlin.plugin.compose` plugin) |
| Compose BOM | 2024.09.00 |
| Activity Compose | 1.8.2 |
| Lifecycle Runtime Compose | 2.8.2 |
| Lifecycle ViewModel Compose | 2.8.2 |
| Gradle wrapper | 8.7 |
| compileSdk / targetSdk | 35 |
| minSdk | 26 |
| Java / Kotlin bytecode target | 17 |

Compose artifact versions come from the Compose BOM
(`gradle/libs.versions.toml`); the `androidx.compose.*` modules are declared
without individual version pins and without `exclude()` statements.

### app/build.gradle.kts

```kotlin
dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.core.ktx)

    implementation(libs.compose.ui)
    implementation(libs.compose.ui.text)
    implementation(libs.compose.material3)
    implementation(libs.compose.foundation)
    implementation(libs.compose.foundation.layout)
    implementation(libs.activity.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.lifecycle.viewmodel.compose)

    debugImplementation(libs.compose.ui.tooling.preview)

    testImplementation(libs.junit)
    testImplementation(libs.json)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
```

### settings.gradle.kts

Repositories: `gradlePluginPortal()`, `google()`, `mavenCentral()` for both
plugin management and dependency resolution. Root project `threatassistant`,
including `:app`.

### local.properties

```
sdk.dir=C:\Users\pares\AppData\Local\Android\Sdk
```

## 2. Build Status

Requirements: **JDK 21** (Android Studio bundled JBR) and **Android SDK 35**.

```bash
# Windows bash
export JAVA_HOME='C:/Program Files/Android/Android Studio/jbr'

./gradlew assembleDebug        # -> app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest    # -> 144 JVM unit tests, 0 failures
```

| Task | Status |
|------|--------|
| `./gradlew :app:dependencies` | SUCCESS — variants resolve correctly |
| `./gradlew :app:compileDebugKotlin` | SUCCESS |
| `./gradlew :app:assembleDebug` | SUCCESS — debug APK generated |
| `./gradlew :app:testDebugUnitTest` | SUCCESS — 144 tests, 0 failures |

## 3. Correction to an Earlier Diagnosis

An earlier revision of this document claimed the build was blocked by "stub"
Compose artifacts in the Gradle cache — common-variant `.aar` files of a few
kilobytes with no compiled classes — and prescribed workarounds: a local Maven
repository, a `libs/` directory of renamed jars, and jar-renaming scripts.

**That diagnosis was incorrect.** The Compose artifacts resolved normally. The
actual build failures were source and build-configuration errors, now fixed:

- Compose dependencies were hard-pinned to versions outside the Compose BOM
  range; they now use the BOM platform (`compose-bom = 2024.09.00`).
- The Java/Kotlin target was `1.8`; it is now `17`.
- `gradle.properties` set `android.injected.test.only.run.unit.tests=true`, an
  Android Studio injected property that does not belong in the project file; it
  was removed.
- Several Compose imports and composables were wrong for the artifacts in use
  (`Row` belongs to `foundation-layout`, `FontWeight`/`TextStyle` to `ui-text`,
  `Chip`/`ChipDefaults` and the Material icons were unavailable, and
  `collectAsStateWithLifecycle` was replaced with `collectAsState`).

Separately, the unused `INTERNET` permission was removed from the manifest; the
app now declares no permissions at all.

No local repository, `libs/` directory, or jar-renaming script is part of the
project — those workaround files were deleted.
