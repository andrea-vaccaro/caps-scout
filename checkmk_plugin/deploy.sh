#!/usr/bin/env bash
# Builds a fresh caps-scout MKP and installs it on a local OMD site.
#
# Bumps manifest.json's patch version before building: the site's package
# manager keys installed packages by (name, version), so re-adding/enabling an
# already-installed version number is a no-op and silently keeps the old
# content - see README "Building and installing the MKP". Bumping every run
# guarantees each deploy is actually picked up.
#
# The site-side steps (mkp add/enable/disable, restart) need to run as the
# site user, which requires root - this script shells out via `sudo su -
# <site>`, so it will prompt for your sudo password once.
#
# Restarts the whole site (`omd restart`) rather than just reloading
# (`cmk -O`): a plain reload leaves the core's already-running check-helper
# processes holding the old plugin code in memory, so the new output never
# shows up until something actually restarts them.
#
# Usage: ./deploy.sh [site] [--skip-agent-build]
#   site                defaults to v250
#   --skip-agent-build  reuse the agent binaries already in agents/ instead of
#                        rebuilding them with cargo (see build_mkp.py --help)
set -euo pipefail
cd "$(dirname "$0")"

SITE="v250"
BUILD_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --skip-agent-build) BUILD_ARGS+=("--skip-agent-build") ;;
    *) SITE="$arg" ;;
  esac
done

OLD_VERSION=$(python3 -c "import json; print(json.load(open('manifest.json'))['version'])")
NEW_VERSION=$(python3 - <<'PY'
import json

path = "manifest.json"
with open(path) as f:
    manifest = json.load(f)
major, minor, patch = manifest["version"].split(".")
manifest["version"] = f"{major}.{minor}.{int(patch) + 1}"
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
print(manifest["version"])
PY
)

echo "Building caps-scout $NEW_VERSION (was $OLD_VERSION)..."
MKP_FILE="caps-scout-${NEW_VERSION}.mkp"
python3 build_mkp.py --manifest manifest.json --output "$MKP_FILE" "${BUILD_ARGS[@]}"

# The site user can't read anything under our home directory (mode 750), so
# stage the package somewhere world-readable first.
TMP_MKP="/tmp/${MKP_FILE}"
cp "$MKP_FILE" "$TMP_MKP"
chmod 644 "$TMP_MKP"

echo "Installing on site '$SITE' (sudo password may be required)..."
sudo su - "$SITE" -c "
  set -e
  mkp add '$TMP_MKP'
  mkp enable caps-scout $NEW_VERSION
  mkp disable caps-scout $OLD_VERSION || true
  omd restart
"

rm -f "$TMP_MKP"
echo "Deployed caps-scout $NEW_VERSION to site $SITE."
echo "Reschedule/rerun the Capabilities Scout check on your hosts to see the new output."
