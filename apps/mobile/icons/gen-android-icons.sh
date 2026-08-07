#!/usr/bin/env bash
# Generate the Pick Android launcher-icon set from the strike48 brand SVGs into
# apps/mobile/icons/res/, which the android build recipe copies over dx's
# generated (stock green-robot) mipmaps. Re-run after changing the source SVGs.
#
# Produces, per density (mdpi/hdpi/xhdpi/xxhdpi/xxxhdpi):
#   - mipmap-<d>/ic_launcher.png        legacy square icon (full appicon SVG)
#   - mipmap-<d>/ic_launcher_round.png  legacy round icon (same art)
#   - mipmap-<d>/ic_launcher_foreground.png  adaptive foreground (mark, safe-zone)
# plus the adaptive-icon XML + background color that reference them.
#
# Requires resvg (rendered via `nix run nixpkgs#resvg`).
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

rm -rf "$RES"
for d in "${!LEGACY[@]}"; do
    dir="$RES/mipmap-$d"
    mkdir -p "$dir"
    lsz=${LEGACY[$d]}
    asz=${ADAPTIVE[$d]}
    resvg --width "$lsz" --height "$lsz" "$APPICON" "$dir/ic_launcher.png"
    cp "$dir/ic_launcher.png" "$dir/ic_launcher_round.png"
    resvg --width "$asz" --height "$asz" "$FOREGROUND" "$dir/ic_launcher_foreground.png"
done

# Adaptive icon: references the foreground PNG + a solid brand background color.
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

echo "Generated Pick Android launcher icons into $RES"
