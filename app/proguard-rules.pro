# R8 keep rules for Jetpack Compose.
# minifyEnabled is currently disabled for both build types; these rules are kept
# so the file remains valid if minification is enabled in a later phase.

-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**
-keepclassmembers class androidx.compose.runtime.** { *; }
