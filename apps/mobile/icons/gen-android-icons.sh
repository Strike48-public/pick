#!/usr/bin/env bash
# Generate the Pick Android launcher-icon set from the strike48 brand SVGs into
# apps/mobile/icons/res/, which the android build recipe copies OVER dx's
# generated (stock green-robot) mipmaps. Re-run after changing the source SVGs.
#
# We emit the legacy icons as .webp with dx's exact filenames (ic_launcher.webp,
# ic_launcher_round.webp) so the copy overwrites dx's in place — no duplicate
# resource, no delete step. Produces, per density (mdpi..xxxhdpi):
#   - mipmap-<d>/ic_launcher.webp        legacy square icon (full appicon SVG)
#   - mipmap-<d>/ic_launcher_round.webp  legacy round icon (same art)
#   - mipmap-<d>/ic_launcher_foreground.webp  adaptive foreground (mark, safe-zone)
# plus the adaptive-icon XML (mipmap-anydpi-v26) + background color (values/).
#
# Requires resvg + imagemagick (rendered via `nix run nixpkgs#...`).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
APPICON="$HERE/strike48-appicon.svg"
FOREGROUND="$HERE/strike48-adaptive-foreground.svg"
RES="$HERE/res"
BG_COLOR="#181817"

# Legacy square launcher px per density (48dp baseline).
declare -A LEGACY=( [mdpi]=48 [hdpi]=72 [xhdpi]=96 [xxhdpi]=144 [xxxhdpi]=192 )
# Adaptive layers are 108dp; px = 108/48 * legacy.
declare -A ADAPTIVE=( [mdpi]=108 [hdpi]=162 [xhdpi]=216 [xxhdpi]=324 [xxxhdpi]=432 )

resvg() { nix run nixpkgs#resvg -- "$@"; }
# SVG -> WEBP at the given size (resvg renders PNG; magick converts to webp).
svg2webp() {
    local svg="$1" size="$2" out="$3" tmp
    tmp="$(mktemp --suffix=.png)"
    resvg --width "$size" --height "$size" "$svg" "$tmp"
    nix run nixpkgs#imagemagick -- "$tmp" "$out"
    rm -f "$tmp"
}

rm -rf "$RES"
for d in "${!LEGACY[@]}"; do
    dir="$RES/mipmap-$d"
    mkdir -p "$dir"
    svg2webp "$APPICON" "${LEGACY[$d]}" "$dir/ic_launcher.webp"
    cp "$dir/ic_launcher.webp" "$dir/ic_launcher_round.webp"
    svg2webp "$FOREGROUND" "${ADAPTIVE[$d]}" "$dir/ic_launcher_foreground.webp"
done

# Adaptive icon (API 26+): references the foreground + a solid brand background.
mkdir -p "$RES/mipmap-anydpi-v26" "$RES/values"
cat > "$RES/mipmap-anydpi-v26/ic_launcher.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
</adaptive-icon>
XML
cp "$RES/mipmap-anydpi-v26/ic_launcher.xml" "$RES/mipmap-anydpi-v26/ic_launcher_round.xml"
cat > "$RES/values/ic_launcher_background.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="ic_launcher_background">$BG_COLOR</color>
</resources>
XML

echo "Generated Pick Android launcher icons (webp) into $RES"
