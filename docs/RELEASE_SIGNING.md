# Release Signing

How Pick release binaries are signed, and the one-time setup the release
workflow needs. Tracking issue: #281.

| Platform | What happens on a tagged release | Where |
|----------|----------------------------------|-------|
| macOS (desktop + headless) | Signed with the Strike48 Developer ID, hardened runtime, notarized by Apple, then checked with Gatekeeper's own notarization test | `scripts/macos-sign-notarize.sh` |
| Windows (desktop) | Signed with Azure Trusted Signing | `release.yml`, `build-desktop-windows` |
| All assets | SHA-256 checksums, plus a Sigstore-signed build provenance attestation for every asset except `SHA256SUMS.txt` itself | `release.yml`, `release` job |

A tag push (`v*`) always signs the macOS binaries. If a required secret is
missing, or Apple rejects the binary, the release fails instead of publishing
an unsigned build. A manual dispatch can set `macos_signing=false` to produce an
unsigned test build; it is published as a prerelease and its notes say it is
unsigned.

## One-time Apple setup

Steps 1 and 2 need the Strike48 Apple Developer **Account Holder**; Apple
restricts creating Developer ID certificates to that role. Step 4 needs admin
on the repository (or the org, for org secrets).

1. **Developer ID Application certificate.**
   - In Keychain Access, use Certificate Assistant, "Request a Certificate From
     a Certificate Authority", saved to disk.
   - On developer.apple.com, under Certificates, add a **Developer ID
     Application** certificate (not Apple Development and not Developer ID
     Installer), upload the request, and download the `.cer`.
   - Double-click the `.cer` to install it, then export the certificate *with
     its private key* from Keychain Access as a `.p12` with a strong password.
2. **App Store Connect API key** for notarization. In App Store Connect, under
   Users and Access, Integrations, App Store Connect API, generate a Team Key
   with the Developer role. Download the `.p8` (Apple offers it only once) and
   note the Key ID and the Issuer ID shown on that page.
3. **Team ID.** Shown under Membership details on developer.apple.com.
4. **Secrets.** Set these on the repository, or as organization secrets scoped
   to the repositories that sign (one certificate, one place to rotate it):

   | Secret | Value |
   |--------|-------|
   | `APPLE_CERTIFICATE_P12` | `base64 -i developer-id.p12` output |
   | `APPLE_CERTIFICATE_PASSWORD` | the `.p12` export password |
   | `APPLE_TEAM_ID` | the 10-character Team ID |
   | `APPLE_API_KEY_P8` | the full contents of the `.p8` file |
   | `APPLE_API_KEY_ID` | the API Key ID |
   | `APPLE_API_ISSUER_ID` | the API Issuer ID |

   ```bash
   gh secret set APPLE_CERTIFICATE_P12 -R Strike48-public/pick < <(base64 -i developer-id.p12)
   gh secret set APPLE_API_KEY_P8 -R Strike48-public/pick < AuthKey_XXXXXXXXXX.p8
   gh secret set APPLE_TEAM_ID -R Strike48-public/pick   # prompts for the value
   ```

   Delete the local `.p12` and `.p8` afterwards, and keep the originals in the
   team password manager. The older `APPLE_ID` and `APPLE_APP_PASSWORD` secrets
   are no longer read and can be removed.

The signing identity is looked up from the certificate by Team ID, so the
legal entity name in the certificate never has to match anything in the
workflow.

## Checking a release

```bash
# Built by this repository's release workflow?
gh attestation verify pick-macos-aarch64.tar.gz --repo Strike48-public/pick

# Signed by Strike48 and notarized?
tar -xzf pick-macos-aarch64.tar.gz
codesign -dv --verbose=2 pentest-connector 2>&1 | grep -E 'Authority|TeamIdentifier'
codesign --verify --strict --check-notarization -R='notarized' pentest-connector
```

## Known limits

- **Who can trigger a signing run.** Anyone who can push a `v*` tag runs the
  signing step with the Developer ID certificate and the API key. Recommended
  admin follow-up: a tag ruleset that limits who may create `v*` tags, and a
  GitHub Environment with required reviewers holding the Apple secrets.

- **No stapled ticket.** The macOS assets are bare executables in a `.tar.gz`,
  and Apple cannot staple a notarization ticket to a bare executable. On first
  launch Gatekeeper fetches the ticket online, so a host with no route to Apple
  can still block a binary downloaded through a browser. Shipping a `.pkg` or
  `.dmg` would allow stapling.
- **Certificate lifetime.** A Developer ID certificate is valid for up to five
  years, but no later than its issuing intermediate (the current G2
  intermediate expires 2031-09-16), so read the expiry date off the issued
  certificate. Binaries signed before it expires stay valid because the
  signature is timestamped, but releases fail at the signing step once it
  lapses, so renew it ahead of time and update `APPLE_CERTIFICATE_P12`.
- **Self-test.** `scripts/macos-sign-notarize.test.sh` runs in the CI
  `check-macos` job and pins the fail-closed paths without any Apple secrets.
  The full sign-and-notarize path only runs on a release.
