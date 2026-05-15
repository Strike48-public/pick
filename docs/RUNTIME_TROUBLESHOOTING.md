# Runtime Troubleshooting Guide

Common runtime errors and how to fix them.

## Resource Seeding Errors

### Error: "Failed to validate base directory: No such file or directory"

**Full error message:**
```
ERROR pentest_core::seed: Failed to seed required resource 'RockYou Wordlist': 
Tool execution error: Failed to validate base directory: No such file or directory (os error 2)
```

**Cause:** The workspace resources directory doesn't exist yet. This happens on first run.

**Fix:** This is automatically fixed in v0.1.1+. The directory is now created automatically.

**Manual fix (if needed):**
```bash
# Create the resources directory
mkdir -p ~/.pick/resources

# Or use custom workspace path from .env
mkdir -p $WORKSPACE_PATH/resources
```

**What are these resources?**
Pick downloads penetration testing resources (wordlists, payloads, etc.) on first run:
- **Required:** RockYou wordlist, common passwords (~135MB)
- **Optional:** XSS payloads, SQL injection payloads, reverse shells, etc.

These are downloaded once and cached locally for offline use.

### Error: Resource download fails

**Error message:**
```
ERROR pentest_core::seed: Failed to seed required resource 'RockYou Wordlist': 
Network error: connection timeout
```

**Causes:**
- No internet connection
- Firewall blocking downloads
- GitHub/source unavailable

**Fix:**

**Option 1: Skip optional resources**
Optional resources will show as warnings (WARN) not errors. Only required resources block startup.

**Option 2: Manual download**
```bash
# Download required resources manually
mkdir -p ~/.pick/resources/wordlists/passwords

# RockYou wordlist (134MB)
curl -L -o ~/.pick/resources/wordlists/passwords/rockyou.txt \
  https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# Common passwords (1MB)
curl -L -o ~/.pick/resources/wordlists/passwords/common-10k.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
```

**Option 3: Use corporate proxy**
```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.corp.com:8080
export HTTPS_PROXY=http://proxy.corp.com:8080

# Then start Pick
./run-pentest.sh headless dev
```

**Option 4: Disable auto-seeding** (not recommended)
If you don't need wordlists/payloads, you can skip the seed check by setting:
```bash
export SKIP_RESOURCE_SEED=true
```

## Connection Errors

### Error: "Connection refused"

**Full error message:**
```
ERROR strike48_connector: Failed to connect to Strike48 backend: 
Connection refused (os error 111)
```

**Cause:** Strike48 backend is not running or wrong host configured.

**Fix:**

1. **Verify backend is running:**
   ```bash
   # Check your .env configuration
   grep STRIKE48_HOST .env
   
   # Try to reach the host
   ping your-backend-hostname
   curl -v https://your-backend-hostname
   ```

2. **Check `.env` configuration:**
   ```bash
   # Required variables
   STRIKE48_HOST=wss://your-server.example.com
   STRIKE48_TENANT=your-tenant-id
   MATRIX_API_URL=https://your-server.example.com
   MATRIX_TENANT_ID=your-tenant-id
   ```

3. **Verify firewall/network:**
   - Check if firewall blocks outbound connections
   - Verify VPN is connected (if required)
   - Check if backend port is open

### Error: "TLS certificate verification failed"

**Full error message:**
```
ERROR strike48_connector: TLS error: 
certificate verify failed: self signed certificate
```

**Cause:** Backend uses self-signed certificate (common in development).

**Fix:**

**For development only:**
```bash
# In .env file
MATRIX_TLS_INSECURE=true
```

**For production:**
- Use valid TLS certificates
- Or provide CA certificate path
- Never use `MATRIX_TLS_INSECURE=true` in production

## Authentication Errors

### Error: "Session token invalid"

**Full error message:**
```
ERROR pentest_ui: Session token validation failed
```

**Cause:** Token expired or invalid.

**Fix:**

1. **Restart Pick** - It will request a new token
2. **Check token in `.env`** (if using JWT instead of OTT):
   ```bash
   # Verify STRIKE48_TOKEN is set and not expired
   grep STRIKE48_TOKEN .env
   ```

3. **Request new token from backend admin**

## Permission Errors

### Error: "Permission denied" on tool execution

**Full error message:**
```
ERROR pentest_tools: Failed to execute tool 'wifi_scan': 
Permission denied (os error 13)
```

**Cause:** Tool requires root privileges (WiFi scanning, packet capture).

**Fix:**

**Option 1: Run with sudo (recommended for desktop)**
```bash
sudo cargo run --package pentest-desktop
# Or
sudo ./run-pentest.sh desktop dev
```

**Option 2: Grant capabilities (Linux only)**
```bash
# Grant specific capabilities instead of full root
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/pentest-desktop

# Then run without sudo
./target/debug/pentest-desktop
```

**Option 3: Use headless mode** (runs as service with appropriate permissions)

### Error: "Operation not permitted" on workspace directory

**Full error message:**
```
ERROR pentest_core: Failed to write to workspace: 
Operation not permitted (os error 1)
```

**Cause:** No write permission to workspace directory.

**Fix:**

1. **Check workspace path:**
   ```bash
   # Default: ~/.local/share/pentest-workspace
   # Or from .env:
   grep WORKSPACE_PATH .env
   ```

2. **Fix permissions:**
   ```bash
   # For default location
   mkdir -p ~/.local/share/pentest-workspace
   chmod 755 ~/.local/share/pentest-workspace
   
   # Or for custom location
   mkdir -p $WORKSPACE_PATH
   chmod 755 $WORKSPACE_PATH
   ```

3. **Check disk space:**
   ```bash
   df -h ~/.local/share/
   ```

## Workspace Errors

### Error: "Workspace path does not exist"

**Cause:** `WORKSPACE_PATH` in `.env` points to non-existent directory.

**Fix:**

```bash
# Check .env
grep WORKSPACE_PATH .env

# Create the directory
mkdir -p /path/from/env
chmod 755 /path/from/env

# Or use default by commenting out WORKSPACE_PATH
# WORKSPACE_PATH=/custom/workspace/path
```

## Still Stuck?

### Generate Diagnostic Report

```bash
# Capture full logs
RUST_LOG=debug ./run-pentest.sh headless dev 2>&1 | tee pick-debug.log

# Check first 100 lines of errors
grep ERROR pick-debug.log | head -100

# Check what resources are missing
ls -la ~/.pick/resources/

# Check workspace
ls -la ~/.local/share/pentest-workspace/
```

### Getting Help

**Include this information when asking for help:**

1. Full error message (not just first line)
2. Output of:
   ```bash
   cat .env  # (remove sensitive tokens first!)
   ls -la ~/.pick/resources/
   ls -la ~/.local/share/pentest-workspace/
   uname -a
   cargo --version
   rustc --version
   ```
3. Steps to reproduce
4. What you've tried already

**Where to get help:**
- GitHub Issues: [Strike48-public/pick/issues](https://github.com/Strike48-public/pick/issues)
- Tag issues with `runtime-error` label

## Prevention

### Pre-flight Checks

Before running Pick:

```bash
# 1. Verify configuration
cat .env

# 2. Test backend connectivity
ping $(grep STRIKE48_HOST .env | cut -d= -f2 | sed 's/wss\?:\/\///')

# 3. Create workspace directories
mkdir -p ~/.pick/resources
mkdir -p ~/.local/share/pentest-workspace

# 4. Check disk space (need ~500MB for resources)
df -h ~/.pick/
```

### Development vs Production

**Development setup:**
```bash
# .env for development
STRIKE48_HOST=ws://localhost:3030
STRIKE48_TLS=false
MATRIX_TLS_INSECURE=true
RUST_LOG=debug
```

**Production setup:**
```bash
# .env for production
STRIKE48_HOST=wss://connectors.example.com
STRIKE48_TLS=true
MATRIX_TLS_INSECURE=false
RUST_LOG=info
```
