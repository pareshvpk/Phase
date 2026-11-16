plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.compose.compiler)
}

// Optional bundled Llama model. The files are large and git-ignored, so the
// task simply does nothing when they are absent; the app then has no AI
// explanations but still builds and runs normally.
val llmAssetsDir = layout.buildDirectory.dir("generated/llmAssets")
val bundledModel = project.file("../models/llama3_2_1b.pte")
val bundledTokenizer = project.file("../models/tokenizer.model")

val prepareLlmAssets = tasks.register<Copy>("prepareLlmAssets") {
    onlyIf { bundledModel.isFile && bundledTokenizer.isFile }
    from(bundledModel) { into("llm") }
    from(bundledTokenizer) { into("llm") }
    into(llmAssetsDir.get().asFile)
}

android {
    namespace = "com.arm.threatassistant"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.arm.threatassistant"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            // Target hardware is Arm; shipping x86_64 doubles the native payload.
            abiFilters += listOf("arm64-v8a")
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
            // TODO: replace with real release keystore before publishing
            signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            isMinifyEnabled = false
        }
    }

    androidResources {
        // Store model files uncompressed so AssetManager.openFd can report their
        // length and the installer can stream them without deflate overhead.
        noCompress += listOf("pte", "model")
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

android.sourceSets.getByName("main").assets.srcDir(llmAssetsDir.get().asFile)

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("Assets") }.configureEach {
    dependsOn(prepareLlmAssets)
}

// Lint reads the generated asset directory too, so it needs the same ordering.
tasks.matching { it.name.contains("Lint", ignoreCase = true) }.configureEach {
    dependsOn(prepareLlmAssets)
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
