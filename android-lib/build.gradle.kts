plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.strike48.pentest_connector.nativelib"
    compileSdk = 35
    buildToolsVersion = "35.0.1"

    defaultConfig {
        minSdk = 24
        // Contribute keep rules to the consuming app's R8 config so the release
        // (minified) build does not strip the JNI-only-referenced classes in
        // this package (ConnectorBridge etc.). Without this the release APK/AAB
        // crashes at first JNI call with ClassNotFoundException. See the file.
        consumerProguardFiles("consumer-rules.pro")
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.6.1")
    // Keystore-backed encrypted key/value store for the chat auth token.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}
