use pentest_platform::desktop::sandbox;
use pentest_platform::CommandExec;
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("=== Testing Sandbox Backend Detection (Fresh Process) ===\n");

    match sandbox::get_sandbox_manager().await {
        Ok(manager) => {
            println!("✅ Sandbox Manager Initialized");
            println!("   Backend: {:?}", manager.backend());
            println!("   Ready: {}", manager.is_ready());

            println!("\n=== Testing nmap with raw sockets ===");
            let platform = pentest_platform::desktop::DesktopPlatform;
            match platform
                .execute_command(
                    "nmap",
                    &["-sS", "127.0.0.1", "-p", "22"],
                    Duration::from_secs(30),
                )
                .await
            {
                Ok(result) => {
                    println!("Exit code: {}", result.exit_code);
                    if result.exit_code == 0 {
                        println!("✅ Raw sockets WORK!");
                    } else {
                        println!("❌ Raw sockets FAILED");
                        println!("Stderr: {}", result.stderr);
                    }
                }
                Err(e) => println!("❌ Command failed: {}", e),
            }
        }
        Err(e) => {
            println!("❌ Failed to initialize: {}", e);
            std::process::exit(1);
        }
    }
}
