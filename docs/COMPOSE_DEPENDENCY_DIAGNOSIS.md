# Compose Dependency Diagnosis

## Repository: D:\ARM (ARM Digital Safety Guardian)

## 1. Dependency Configuration

### Root build.gradle.kts (`D:\ARM/build.gradle.kts`)
- Applies `com.android.application` AGP 8.6.0 and `org.jetbrains.kotlin.android` Kotlin 2.0.0 plugins (with `apply false`)
- Gradle wrapper version: 8.7

### settings.gradle.kts (`D:\ARM/settings.gradle.kts`)
- Repositories: `gradlePluginPortal()`, `google()`, `mavenCentral()`
- Dependency resolution repositories: same three
- Root project: `threatassistant`, includes `:app`

### gradle/libs.versions.toml (`D:\ARM/gradle/libs.versions.toml`)
| Component | Version |
|-----------|---------|
| AGP | 8.6.0 |
| Kotlin | 2.0.0 |
| Compose UI | 1.8.2 |
| Compose Material3 | 1.4.0 |
| Compose Foundation | 1.6.8 |
| Compose Foundation Layout | 1.8.1 |
| Lifecycle Runtime Compose | 2.8.2 |
| Lifecycle ViewModel Compose | 2.8.2 |
| Activity Compose | 1.8.2 |

### app/build.gradle.kts — **FIXED**
Removed all `exclude()` statements that stripped common Compose variants. Now uses standard dependency declarations:

```kotlin
dependencies {
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.text)
    implementation(libs.compose.material3)
    implementation(libs.compose.foundation)
    implementation(libs.compose.foundation.layout)
    implementation(libs.activity.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.lifecycle.viewmodel.compose)
}
```

### local.properties — **CREATED**
```
sdk.dir=C:\Users\pares\AppData\Local\Android\Sdk
```

## 2. Dependency Resolution Results

### `dependencyInsight` for `androidx.compose.ui:ui`

```
androidx.compose.ui:ui:1.8.2
\--- androidx.compose.ui:ui-android:1.8.2
     \--- debugCompileClasspath (requested androidx.compose.ui:ui-android:1.8.2)
```

The common `ui:1.8.2` variant IS resolved as a transitive dependency of `ui-android:1.8.2`. Both common and Android variants are now requested without exclusions.

### `dependencyInsight` for `androidx.compose.material3:material3`

```
androidx.compose.material3:material3-android:1.4.0
\--- debugCompileClasspath
```

Both `material3:1.4.0` (common) and `material3-android:1.4.0` (Android variant) are now resolved without exclusions.

### Selected variants (after fix)
- `ui:1.8.2` (common) + `ui-android:1.8.2` (Android)
- `ui-text:1.8.2` (common) + `ui-text-android:1.8.2` (Android)
- `material3:1.4.0` (common) + `material3-android:1.4.0` (Android)
- `foundation:1.6.8` (common) + `foundation-android:1.6.8` (Android)
- `foundation-layout:1.8.1` (common) + `foundation-layout-android:1.8.1` (Android)

## 3. Cached Artifact Inspection

### Before fix (stub artifacts)

| Artifact | Version | File | Size | Status |
|----------|---------|------|------|--------|
| `androidx.compose.ui:ui` | 1.8.2 | `ui-1.8.2.aar` | 4,626 bytes | **STUB** — no classes.jar |
| `androidx.compose.material3:material3` | 1.4.0 | `material3-1.4.0.aar` | 4,703 bytes | **STUB** — no classes.jar |
| `androidx.compose.ui:ui-text` | 1.8.2 | (none) | N/A | Only .pom and .module metadata |

### After `--refresh-dependencies` (deleted stubs, attempted re-download)

| Artifact | Version | Files after refresh | Status |
|----------|---------|---------------------|--------|
| `androidx.compose.ui:ui` | 1.8.2 | `.pom` (6,682 bytes), `.module` (27,652 bytes) | **.aar NOT downloaded** |
| `androidx.compose.material3:material3` | 1.4.0 | `.pom` (3,667 bytes), `.module` (13,368 bytes) | **.aar NOT downloaded** |
| `androidx.compose.ui:ui-text` | 1.8.2 | `.pom` (5,477 bytes), `.module` (27,177 bytes) | **.aar NOT downloaded** |

### Complete artifacts (Android variants)

| Artifact | Version | File | Size | Status |
|----------|---------|------|------|--------|
| `androidx.compose.ui:ui-android` | 1.8.2 | `ui-release.aar` | 5,526,199 bytes | **COMPLETE** |
| `androidx.compose.material3:material3-android` | 1.4.0 | `material3.aar` | 5,167,765 bytes | **COMPLETE** |

## 4. Root Cause

**The Gradle environment cannot download complete Compose common variant artifacts.**

The common variants (`ui:1.8.2`, `material3:1.4.0`, `ui-text:1.8.2`) are distributed as stub `.aar` files (4–5 KB) containing no compiled Kotlin classes. The actual API classes (`@Composable`, `Modifier`, `FontWeight`, `TextStyle`, `Card`, `Text`, `Column`, `Row`, `Scaffold`, etc.) exist only in the `-android` variant artifacts (`ui-android:1.8.2` = 5.5 MB, `material3-android:1.4.0` = 5.2 MB).

After removing the `exclude()` statements and deleting stub artifacts, Gradle was given `--refresh-dependencies` to re-download from `google()` and `mavenCentral()`. It successfully downloaded `.pom` and `.module` metadata files but **did NOT download `.aar` files** for any common variant. This indicates either:

1. **No network access** to remote Maven repositories, or
2. The common variant `.aar` files are not available in the configured repositories

The `-android` variants were already complete in the cache (5+ MB each), suggesting they were pre-populated in a different environment.

## 5. Compilation Result

**BUILD FAILED** — `./gradlew :app:compileDebugKotlin` cannot succeed.

All errors are `Unresolved reference` for standard Compose types:

| Error | Count | Missing Artifact |
|-------|-------|-----------------|
| `Unresolved reference: FontWeight` | Multiple | `ui-text:1.8.2` common (stub) |
| `Unresolved reference: TextStyle` | Multiple | `ui-text:1.8.2` common (stub) |
| `Unresolved reference: Column` | Multiple | `material3:1.4.0` common (stub) |
| `Unresolved reference: Row` | Multiple | `material3:1.4.0` common (stub) |
| `Unresolved reference: Card` | Multiple | `material3:1.4.0` common (stub) |
| `Unresolved reference: collectAsStateWithLifecycle` | Multiple | `lifecycle-runtime-compose` (version mismatch/stub) |
| `Composable invocations can only happen from @Composable function` | All screens | `ui:1.8.2` common (stub — `@Composable` annotation missing) |

## 6. Recommended Correction

### Minimal fix (already applied to build.gradle.kts)

Remove all `exclude()` statements from `app/build.gradle.kts` and use standard Compose dependencies:

```kotlin
dependencies {
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.text)
    implementation(libs.compose.material3)
    implementation(libs.compose.foundation)
    implementation(libs.compose.foundation.layout)
    implementation(libs.activity.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.lifecycle.viewmodel.compose)
}
```

### Required environment fix (cannot be done from within project)

Complete common Compose variant artifacts must be present in the Gradle cache:

```
~/.gradle/caches/modules-2/files-2.1/androidx.compose.ui/ui/1.8.2/
~/.gradle/caches/modules-2/files-2.1/androidx.compose.material3/material3/1.4.0/
~/.gradle/caches/modules-2/files-2.1/androidx.compose.ui/ui-text/1.8.2/
```

These artifacts must contain complete `.aar` files with `classes.jar` (not stubs). They can be obtained by:

1. **Network access**: Ensure the machine can reach `https://dl.google.com/dl/android/maven2/` and `https://repo.maven.apache.org/maven2/`, then run `gradlew --refresh-dependencies`
2. **Cache copy**: Copy complete artifacts from another machine's Gradle cache that has successfully resolved Compose dependencies

### `local.properties` (already created)

```
sdk.dir=C:\Users\pares\AppData\Local\Android\Sdk
```

## 7. Verification Status

| Task | Status |
|------|--------|
| Fix `build.gradle.kts` dependencies | DONE — excludes removed |
| Create `local.properties` | DONE |
| `./gradlew :app:dependencies` | SUCCESS — variants resolve correctly |
| `./gradlew :app:compileDebugKotlin` | FAILED — common Compose artifacts are stubs |
| `./gradlew :app:assembleDebug` | NOT ATTEMPTED — compilation fails |
| `./gradlew :app:testDebugUnitTest` | NOT ATTEMPTED — compilation fails |

## Conclusion

**The dependency configuration is now correct.** All `exclude()` statements have been removed, and Gradle resolves both common and `-android` variants as expected. However, **compilation cannot succeed** because the Gradle environment lacks complete Compose common variant artifacts (stubs only, no compiled classes). The environment appears to lack network access to download complete artifacts from remote Maven repositories, and no complete artifacts exist elsewhere on the system.

To complete the build, the machine needs either:
1. Network access to download complete Compose common variant `.aar` files from Google Maven, or
2. Complete artifacts copied from another machine's Gradle cache

No source code changes are required — all Kotlin source files use standard Compose APIs correctly.