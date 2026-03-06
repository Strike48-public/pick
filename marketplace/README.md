# Marketplace Manifests

This directory contains TOML manifests that describe connector applications for the Strike48 marketplace/app store.

## Manifest Format

Each connector app has a `.toml` manifest file that contains:

- **App metadata** - ID, name, description, version, author
- **Platform availability** - Which platforms the app supports
- **Download links** - URLs pointing to GitHub Releases
- **Features** - What capabilities the app provides
- **Requirements** - System requirements per platform
- **Media** - Screenshots, icons, banners
- **Changelog** - Recent version history

## How It Works

1. **CI builds the app** - GitHub Actions builds for all platforms
2. **CI creates a release** - Artifacts uploaded to GitHub Releases
3. **CI updates the manifest** - Version and URLs updated automatically
4. **Marketplace reads manifests** - Static site generator builds the UI

## Creating a New Connector Manifest

1. Copy `_template.toml` to `your-connector.toml`
2. Fill in your app details
3. Set up GitHub Actions to build and release
4. The marketplace will automatically pick up new manifests

## Manifest Schema

See `_schema.toml` for the full schema documentation.

## Local Development

To validate a manifest:

```bash
# Install tomlfmt (or any TOML validator)
cargo install tomlfmt

# Validate syntax
tomlfmt --check marketplace/your-connector.toml
```

## Manifest Discovery

The marketplace site discovers manifests in two ways:

1. **This repository** - All `.toml` files in this directory (except `_*.toml`)
2. **External repositories** - Via `marketplace/index.toml` registry

## Index File

The `index.toml` file lists all known connectors:

```toml
[[connectors]]
id = "com.strike48.pentest-connector"
manifest = "pentest-connector.toml"
# Or for external repos:
# manifest_url = "https://raw.githubusercontent.com/org/repo/main/marketplace/connector.toml"
```
