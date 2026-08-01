// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/spf13/viper"
)

// configPartitionBytes is the fixed size of EVE's CONFIG partition. A
// config.img of any other size could not be written into it.
const configPartitionBytes = 5 << 20

// liveImageCurrent selects the newest local build via the dist symlink.
const liveImageCurrent = "current"

// eveVersionDir matches a dist version directory, which is what `make live`
// names after the EVE version. Used only to decide whether a directory name is
// worth reporting as the version.
var eveVersionDir = regexp.MustCompile(`^\d+\.\d+\.\d+-`)

// localLiveImage is a locally built EVE live image and the files that go with
// it. Every field is an existing path by the time this is returned.
type localLiveImage struct {
	DiskPath      string
	ConfigImgPath string
	FirmwareDir   string
	Version       string
}

// resolveLocalLiveImage resolves the local live image configuration, or returns
// (nil, nil) when the feature is off and the container path should be used.
func resolveLocalLiveImage(zarch string) (*localLiveImage, error) {
	setting := viper.GetString(constants.EVELiveImageEnv)
	distRoot := viper.GetString(constants.EVEDistDirEnv)
	if distRoot == "" && setting == liveImageCurrent {
		return nil, fmt.Errorf(
			"%s is not set: it must point at the EVE dist directory to resolve %s=%s",
			constants.EnvPrefix+constants.EVEDistDirEnv,
			constants.EnvPrefix+constants.EVELiveImageEnv, liveImageCurrent)
	}
	return resolveLocalLiveImageIn(distRoot, zarch, setting,
		viper.GetString(constants.EVEFirmwareDirEnv))
}

// resolveLocalLiveImageIn is resolveLocalLiveImage with the dist root and the
// two settings injected, so it can be tested without touching the environment.
func resolveLocalLiveImageIn(distRoot, zarch, setting, firmwareOverride string) (
	*localLiveImage, error) {

	if setting == "" {
		return nil, nil
	}

	diskPath := setting
	if setting == liveImageCurrent {
		diskPath = filepath.Join(distRoot, zarch, liveImageCurrent, "live.qcow2")
	}
	resolved, err := filepath.EvalSymlinks(diskPath)
	if err != nil {
		return nil, fmt.Errorf(
			"no local EVE live image at %q: %w (run `make live`, or set %s to a path)",
			diskPath, err, constants.EVELiveImageEnv)
	}

	verDir := filepath.Dir(resolved)
	img := &localLiveImage{
		DiskPath:      resolved,
		ConfigImgPath: filepath.Join(verDir, "installer", "config.img"),
		FirmwareDir:   filepath.Join(verDir, "installer", "firmware"),
	}
	if firmwareOverride != "" {
		img.FirmwareDir = firmwareOverride
	}
	if base := filepath.Base(verDir); eveVersionDir.MatchString(base) {
		img.Version = base
	}

	info, err := os.Stat(img.ConfigImgPath)
	if err != nil {
		return nil, fmt.Errorf("local EVE build is incomplete, no config.img at %q: %w",
			img.ConfigImgPath, err)
	}
	if info.Size() != configPartitionBytes {
		return nil, fmt.Errorf("config.img at %q is %d bytes, expected %d",
			img.ConfigImgPath, info.Size(), configPartitionBytes)
	}
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		if _, err := os.Stat(filepath.Join(img.FirmwareDir, f)); err != nil {
			return nil, fmt.Errorf("local EVE build is missing firmware %q: %w", f, err)
		}
	}
	return img, nil
}

// liveImageShaSidecar is the name of the hash cache file written next to the
// image. `make live` creates a new version directory per build, so a build
// this file doesn't already know about naturally has no sidecar yet -- that
// absence is the invalidation, no mtime bookkeeping needed. Format is one
// greppable line: "<hex sha256>  <size in bytes>\n".
const liveImageShaSidecar = "image-sha"

// liveImageSHA256 returns the hex sha256 of path, reusing the value recorded
// in the sidecar file when its recorded size still matches the file's
// current size. EVETEST_EVE_LIVE_IMAGE may point at an arbitrary path outside
// a dist version directory, where content can change without a new
// directory, so the size check guards against reusing a stale hash there.
//
// A cache read or write failure only costs time (falls back to recomputing);
// it never becomes an error.
func liveImageSHA256(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat %q: %w", path, err)
	}
	cachePath := filepath.Join(filepath.Dir(path), liveImageShaSidecar)

	if data, err := os.ReadFile(cachePath); err == nil {
		if sum, size, ok := parseLiveImageShaSidecar(data); ok && size == info.Size() {
			return sum, nil
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open %q: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to read %q: %w", path, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))

	line := fmt.Sprintf("%s  %d\n", sum, info.Size())
	// World-readable: it's a content hash, nothing secret, and the harness
	// may be writing it as root inside a container into the developer's own
	// bind-mounted dist tree.
	// A cache write failure only costs time on the next run.
	_ = os.WriteFile(cachePath, []byte(line), 0o644)
	chownToHostUser(cachePath)
	return sum, nil
}

// chownToHostUser hands path back to the developer when running inside the
// evetest container as root. EVETEST_HOST_UID/EVETEST_HOST_GID are set by the
// container runtime (see evetest/Makefile), not user-facing configuration, so
// they are read directly rather than via a constants.* env var. A chown
// failure -- including the common case of running outside the container,
// where the variables are unset -- only costs the developer a `sudo chown`;
// it is not an error.
func chownToHostUser(path string) {
	uid, uidErr := strconv.Atoi(os.Getenv("EVETEST_HOST_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("EVETEST_HOST_GID"))
	if uidErr != nil || gidErr != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}

// parseLiveImageShaSidecar parses the "<hex sha256>  <size>\n" sidecar format.
func parseLiveImageShaSidecar(data []byte) (sum string, size int64, ok bool) {
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return "", 0, false
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return fields[0], size, true
}
