#!/bin/sh
# Assemble the installable Frieren module from src/ into dist/.
#
#   dist/wireless_assessment/      <- copy this folder onto the device
#     manifest.json
#     Wireless_assessmentController.php
#     module.umd.js
#   dist/wireless_assessment.tar.gz  <- or extract this on the device
#
# The device folder MUST be named exactly "wireless_assessment" (it is the
# Frieren routing key), so the module ends up at /frieren/modules/wireless_assessment/.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/src"
NAME="wireless_assessment"
OUT="$ROOT/dist/$NAME"

# 1) Rebuild the gzipped UMD bundle from its source (raw gzip, no bundler).
#    Skips gracefully if node is unavailable and a prebuilt bundle exists.
if command -v node >/dev/null 2>&1; then
    node --check "$SRC/module.umd.source.js"
    gzip -9 -n -c "$SRC/module.umd.source.js" > "$SRC/module.umd.js"
elif [ ! -f "$SRC/module.umd.js" ]; then
    echo "error: node not found and no prebuilt src/module.umd.js" >&2
    exit 1
fi

# 2) Copy only the files the device needs (no authored source, no scaffolding):
#    manifest, the PHP controller + its backend helper classes (Wa*.php, autoloaded
#    on demand by Frieren's PSR-4 fallback), and the gzipped UMD frontend bundle.
rm -rf "$OUT"
mkdir -p "$OUT"
cp "$SRC/manifest.json"                     "$OUT/manifest.json"
cp "$SRC/Wireless_assessmentController.php" "$OUT/Wireless_assessmentController.php"
for helper in "$SRC"/Wa*.php; do
    cp "$helper" "$OUT/$(basename "$helper")"
done
cp "$SRC/module.umd.js"                     "$OUT/module.umd.js"

# 3) Tarball whose top-level directory is the module name, so it can be
#    extracted straight into the modules root: tar -xzC /frieren/modules -f ...
( cd "$ROOT/dist" && tar -czf "$NAME.tar.gz" "$NAME" )

echo "Built:"
echo "  dist/$NAME/            (copy this folder to /frieren/modules/)"
echo "  dist/$NAME.tar.gz      (or: tar -xzC /frieren/modules -f $NAME.tar.gz)"
