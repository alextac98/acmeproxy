#!/bin/sh
set -eu
# Pinned acme.sh 3.1.4 source. Updating requires reviewing adapters and this checksum.
revision=3661fd86b6304115e42f43910e6dd452ab9866d6
checksum=9af3ad3d775a5782246df4cdd4b4e7b9b3179deb63c509b10e3ba0433093a884
destination=${1:-.local/acme.sh}
if [ -e "$destination/acme.sh" ]; then
  echo "Destination already contains acme.sh; choose an empty directory." >&2
  exit 1
fi
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT HUP INT TERM
curl --fail --silent --show-error --location "https://codeload.github.com/acmesh-official/acme.sh/tar.gz/$revision" -o "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --status
mkdir -p "$destination"
tar -xzf "$archive" --strip-components=1 -C "$destination"
echo "Installed acme.sh 3.1.4 adapters in $destination"
