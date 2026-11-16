# R8 keep rules for the release build (minify + resource shrinking).

# ExecuTorch loads its runtime and LLM extension through JNI/reflection.
-keep class org.pytorch.executorch.** { *; }
-keep class com.facebook.jni.** { *; }
-keep class com.facebook.soloader.** { *; }
-keepclasseswithmembernames class * { native <methods>; }
-dontwarn org.pytorch.executorch.**
-dontwarn javax.annotation.Nullable

# Jetpack Compose.
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**
-keepclassmembers class androidx.compose.runtime.** { *; }
