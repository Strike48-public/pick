# Keep all classes in the connector package — they're called via JNI from Rust
-keep class com.strike48.pentest_connector.** { *; }
