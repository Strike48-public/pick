fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        // Delay-load pcap DLLs so the binary doesn't crash on startup
        // if Npcap isn't installed. We check at runtime before calling
        // any pcap functions.
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
}
