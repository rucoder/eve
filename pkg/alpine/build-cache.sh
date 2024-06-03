#!/bin/sh
set -e

bail() {
  echo "$*"
  exit 1
}

[ "$#" -gt 2 ] || bail "Usage: $0 <alpine version> <path to the cache> [packages...]"

ALPINE_VERSION=$1

echo "Bulding cache for [$ALPINE_VERSION]"

if [ "$ALPINE_VERSION" != "edge" ]; then
  ALPINE_VERSION=v$1
fi

ALPINE_REPO="$(cat /etc/apk/cache.url)/$ALPINE_VERSION"
CACHE="$2/$(apk --print-arch)"
ROOTFS="$CACHE/../rootfs"
shift 2

echo "Using cache [$CACHE] and repo [$ALPINE_REPO]"

# optionally initialize the cache
[ ! -d "$CACHE" ] && mkdir -p "$CACHE"

# check for existing packages in the cache: we NEVER overwrite packages
#shellcheck disable=SC2068
for p in ${@}; do
  [ -f "$(echo "$CACHE/${p}"-[0-9]*)" ] || PKGS="$PKGS $p"
done

# remove the last path element in ALPINE_REPO and create 3 combiantions with 'main', 'community' and 'testing'
# we have to use all 3 repositories to fetch the missing packages
ALPINE_REPO=$(echo "$ALPINE_REPO" | sed 's/\/[^/]*$//')
ALPINE_REPOS="-X $ALPINE_REPO/main -X $ALPINE_REPO/community -X $ALPINE_REPO/testing"
# fetch the missing packages
# shellcheck disable=SC2086
if [ -n "$PKGS" ]; then
  apk fetch $ALPINE_REPOS --no-cache --recursive -o "$CACHE" $PKGS || \
  apk fetch $ALPINE_REPOS --no-cache -o "$CACHE" $PKGS
fi

# index the cache
rm -f "$CACHE"/APKINDEX*
apk index --rewrite-arch "$(apk --print-arch)" -o "$CACHE/APKINDEX.unsigned.tar.gz" "$CACHE"/*.apk
cp "$CACHE/APKINDEX.unsigned.tar.gz" "$CACHE/APKINDEX.tar.gz"
abuild-sign "$CACHE/APKINDEX.tar.gz"

mkdir -p "$ROOTFS/etc/apk"
cp -r /etc/apk/keys "$ROOTFS/etc/apk"
cp ~/.abuild/*.rsa.pub "$ROOTFS/etc/apk/keys/"
cp ~/.abuild/*.rsa.pub /etc/apk/keys/
echo "$CACHE/.." > "$ROOTFS/etc/apk/repositories"
apk add -X "$CACHE/.." --no-cache --initdb -p "$ROOTFS" busybox
