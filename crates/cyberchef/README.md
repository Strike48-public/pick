# CyberChef Integration for Pick

Comprehensive CyberChef integration providing data transformation, encoding/decoding, hashing, and analysis capabilities within Pick.

## Features

### 1. CyberChef Tool (`cyberchef`)

Programmatic recipe execution via the Pick tool registry.

**Parameters:**
- `recipe` - Recipe name from library or custom recipe JSON
- `input` - Data to process
- `input_type` - Input format: `string` (default), `hex`, `base64`
- `list_recipes` - Boolean flag to list all available recipes

**Example Usage:**
```json
{
  "tool": "cyberchef",
  "parameters": {
    "recipe": "base64_decode",
    "input": "SGVsbG8gV29ybGQ="
  }
}
```

### 2. Recipe Library

20+ pre-built recipes for common pentest operations:

**Encoding/Decoding:**
- `base64_decode` / `base64_encode`
- `url_decode` / `url_encode`
- `hex_decode` / `hex_encode`

**Hashing:**
- `hash_md5`, `hash_sha1`, `hash_sha256`
- `hash_all` - Calculate all common hashes

**Cryptography:**
- `xor_bruteforce` - Brute force XOR cipher
- `rot13` - ROT13 cipher

**Data Extraction:**
- `extract_urls`, `extract_ips`, `extract_emails`, `extract_domains`

**Compression:**
- `gzip_decompress`, `zlib_decompress`

**Analysis:**
- `magic` - Auto-detect encoding and decode
- `jwt_decode` - Decode JWT tokens

### 3. Rust-Native Executor

Fast, dependency-free execution for common operations:
- Base64 encoding/decoding
- Hex encoding/decoding
- URL encoding/decoding
- MD5, SHA-1, SHA-256 hashing
- ROT13 cipher

## Architecture

```
CyberChefTool (PentestTool implementation)
    ↓
RecipeLibrary (Pre-built recipes)
    ↓
RecipeExecutor (Rust-native operations)
```

## Implementation Status

✅ **Phase 1: Complete**
- CyberChef tool implementation
- Recipe library with 20 recipes
- Rust-native executor
- Full test coverage (14 tests passing)
- Tool registry integration

🚧 **Future Phases:**
- Phase 2: Embedded CyberChef UI (iframe integration)
- Phase 3: Node.js bridge for full CyberChef operations
- Phase 4: Dashboard quick actions
- Phase 5: Recipe persistence and sharing

## Testing

Run tests:
```bash
cargo test --package pentest-cyberchef
```

All 14 tests pass, covering:
- Recipe library management
- Tool schema and parameters
- Base64, hex, URL encoding/decoding
- Hashing operations
- Chained operations
- Error handling

## Usage in Pick

The CyberChef tool is automatically registered in the tool registry and available to:
- AI assistants via tool calls
- Manual execution via Pick's tool interface
- Other tools for data transformation

List available recipes:
```json
{
  "tool": "cyberchef",
  "parameters": {
    "list_recipes": true
  }
}
```

Execute a recipe:
```json
{
  "tool": "cyberchef",
  "parameters": {
    "recipe": "base64_decode",
    "input": "SGVsbG8gV29ybGQ="
  }
}
```

## Dependencies

- `base64` - Base64 encoding/decoding
- `hex` - Hexadecimal encoding/decoding
- `urlencoding` - URL encoding/decoding
- `md5`, `sha1`, `sha2` - Cryptographic hashing
- `serde_json` - Recipe parsing
- `anyhow` - Error handling

No external runtime dependencies required for current operations.

## Future Enhancements

1. **Node.js Bridge** - Full CyberChef operation support
2. **UI Integration** - Embedded CyberChef web interface
3. **Custom Recipes** - Save and share custom recipes
4. **Batch Processing** - Process multiple inputs
5. **Recipe Templates** - Parameterized recipes
6. **WASM Compilation** - Eliminate all external dependencies

## License

MIT
