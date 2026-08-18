# Consumer ProGuard/R8 keep rules for the Pick android-lib module.
#
# The Rust core reaches every class here reflectively over JNI (ConnectorBridge
# @JvmStatic entrypoints, the Activity/Service classes registered in the
# manifest, and the NSD/MediaProjection callbacks). R8 sees no compile-time
# reference from app Kotlin/Java code, so in a MINIFIED release build it strips
# the whole package — the app then crashes at first JNI call with
# `ClassNotFoundException: com.strike48.pick.ConnectorBridge`.
# Debug builds don't minify, which is why this only bites release/AAB builds.
#
# These rules are `consumerProguardFiles`, so they are contributed automatically
# to the consuming app module's R8 configuration. Keeping them in the library
# module (not app/proguard-rules.pro) means they survive `dx build` regenerating
# the app Gradle project.
-keep class com.strike48.pick.** { *; }
-keepclassmembers class com.strike48.pick.** { *; }

# androidx.security-crypto pulls in Google Tink, which references compile-only
# annotations (javax.annotation.Nullable, error-prone/j2objc annotations) that
# are not on the Android runtime classpath. Keeping the package above makes R8
# actually process the Tink chain (previously it was stripped wholesale), so it
# now needs these -dontwarn rules to complete. They only silence warnings about
# absent compile-only annotations; no runtime behavior is affected.
-dontwarn javax.annotation.**
-dontwarn com.google.errorprone.annotations.**
-dontwarn com.google.j2objc.annotations.**
