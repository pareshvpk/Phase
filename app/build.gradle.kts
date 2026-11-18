import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.compose.compiler)
}

// The Llama model is NOT bundled in the APK: ExecuTorch needs a real file, so a
// bundled model ended up stored twice (APK + extracted copy, ~3.5 GB). The app
// downloads it once instead. Set these in gradle.properties or with -P when a
// public download location exists; when empty, no download is offered and a
// copy placed on the phone (e.g. via adb) is still used.
fun armProperty(name: String): String = (project.findProperty(name) as String?)?.trim().orEmpty()
val llmModelUrl = armProperty("armLlmModelUrl")
val llmTokenizerUrl = armProperty("armLlmTokenizerUrl")
val llmModelSha256 = armProperty("armLlmModelSha256")
val llmModelBytes = armProperty("armLlmModelBytes").toLongOrNull() ?: 0L

android {
    namespace = "com.arm.threatassistant"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.arm.threatassistant"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "2.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "LLM_MODEL_URL", "\"$llmModelUrl\"")
        buildConfigField("String", "LLM_TOKENIZER_URL", "\"$llmTokenizerUrl\"")
        buildConfigField("String", "LLM_MODEL_SHA256", "\"$llmModelSha256\"")
        buildConfigField("long", "LLM_MODEL_BYTES", "${llmModelBytes}L")

        ndk {
            // Target hardware is Arm; shipping x86_64 doubles the native payload.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    // Release signing comes from keystore.properties in the project root (git-ignored):
    //   storeFile=<absolute path to .jks>  storePassword=...  keyAlias=...  keyPassword=...
    // Without that file, release builds fall back to the debug key so anyone can build.
    val keystoreProps = Properties().apply {
        val f = rootProject.file("keystore.properties")
        if (f.isFile) f.inputStream().use { load(it) }
    }
    val hasReleaseKey = keystoreProps.getProperty("storeFile")?.let { file(it).isFile } == true
    signingConfigs {
        if (hasReleaseKey) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName(if (hasReleaseKey) "release" else "debug")
        }
        debug {
            isMinifyEnabled = false
        }
    }


    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            // Keep native libraries uncompressed inside the APK (no double copy).
            useLegacyPackaging = false
        }
    }
}


dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.core.ktx)
    implementation(libs.appcompat)

    implementation(libs.compose.ui)
    implementation(libs.compose.ui.text)
    implementation(libs.compose.material3)
    implementation(libs.compose.foundation)
    implementation(libs.compose.foundation.layout)
    implementation(libs.activity.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.lifecycle.viewmodel.compose)
    implementation(libs.executorch.android)

    debugImplementation(libs.compose.ui.tooling.preview)

    testImplementation(libs.junit)
    testImplementation(libs.json)

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    // Pin core to match runner/monitor; the transitive 1.5.0 crashes ActivityScenario on device.
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
