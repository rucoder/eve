// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// liveUploadsSubdir holds uploaded-but-not-yet-installed live images. A sibling
// of templates/ so the template sweep never sees a partial upload.
const liveUploadsSubdir = ".live-uploads"

// liveUploadsDir is where staged live image uploads (and their in-progress
// ".part" files) live, under the broker's image dir.
func liveUploadsDir(imageDir string) string {
	return filepath.Join(imageDir, liveUploadsSubdir)
}

// liveUploadPath is where an uploaded live image tar is staged before install.
func liveUploadPath(imageDir, sha string) string {
	return filepath.Join(liveUploadsDir(imageDir), sha+".tar")
}

// removeStaleLiveUploads deletes every staged live-image upload -- both
// completed tars and in-progress ".part" files -- left behind by a killed
// broker, or by a client that aborted before a successful BuildImage retry
// ever consumed and removed the tar. Called once at startup, alongside
// removeStaleTmpDirs. A non-owner broker must skip this: the uploads it would
// sweep may belong to another broker's upload currently in progress, not to a
// killed one.
func (c *templateCache) removeStaleLiveUploads() error {
	if !c.owner {
		return nil
	}
	dir := liveUploadsDir(c.imageDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read live upload dir %q: %w", dir, err)
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if err := os.RemoveAll(path); err != nil {
			c.log.Warnf("Failed to remove stale live image upload %q: %v", path, err)
			continue
		}
		c.log.Infof("Removed stale live image upload %q", path)
	}
	return nil
}

// unpackLiveTemplate returns a templateBuilder that installs a template from an
// uploaded tar instead of building one with the EVE container. Everything the
// container path produces is already in the tar, because `make live` emits
// live.qcow2, config.img and the OVMF firmware as separate files.
//
// wantSHA256 is the hash the client declared for disk.qcow2 -- the same value
// that was used to compute the template's cache key and the upload's path on
// disk. It is verified against the bytes actually received, not merely
// asserted by the client: the cache key, the tar's storage path and the
// content itself must all agree, or a mismatched or corrupted upload would
// otherwise be installed as if it were the image the client claimed.
func unpackLiveTemplate(tarPath, wantSHA256 string) templateBuilder {
	return func(ctx context.Context, log *logrus.Entry, dstDir string) (gptPartition, error) {
		var none gptPartition

		f, err := os.Open(tarPath)
		if err != nil {
			return none, fmt.Errorf("failed to open the uploaded live image %q: %w",
				tarPath, err)
		}
		defer f.Close()

		seen := map[string]bool{}
		diskHasher := sha256.New()
		tr := tar.NewReader(f)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return none, fmt.Errorf("failed to read the uploaded live image: %w", err)
			}
			// A tar is attacker-shaped input; refuse anything that would land
			// outside dstDir rather than trusting the member name.
			clean := filepath.Clean(hdr.Name)
			if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
				return none, fmt.Errorf("upload contains an unsafe path %q", hdr.Name)
			}
			target := filepath.Join(dstDir, clean)
			if hdr.Typeflag == tar.TypeDir {
				if err := os.MkdirAll(target, 0o755); err != nil {
					return none, err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return none, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return none, err
			}
			// The 2 GB disk image is hashed as it is written, not re-read
			// afterwards: a second pass over the whole file would double the
			// I/O this check costs.
			var dst io.Writer = out
			if clean == templateDiskFile {
				dst = io.MultiWriter(out, diskHasher)
			}
			if _, err := io.Copy(dst, tr); err != nil {
				out.Close()
				return none, fmt.Errorf("failed to write %q: %w", target, err)
			}
			if err := out.Close(); err != nil {
				return none, err
			}
			seen[clean] = true
		}

		for _, required := range []string{templateDiskFile, templateConfigImgFile} {
			if !seen[required] {
				return none, fmt.Errorf("upload is missing %q", required)
			}
		}

		if gotSHA256 := hex.EncodeToString(diskHasher.Sum(nil)); gotSHA256 != wantSHA256 {
			return none, fmt.Errorf(
				"uploaded live image disk hash mismatch: got %s, want %s",
				gotSHA256, wantSHA256)
		}

		diskPath := filepath.Join(dstDir, templateDiskFile)
		head, err := readDiskHead(ctx, diskPath)
		if err != nil {
			return none, fmt.Errorf("failed to read GPT of %q: %w", diskPath, err)
		}
		part, err := findGPTPartition(head, gptConfigPartName)
		if err != nil {
			return none, fmt.Errorf("failed to locate the CONFIG partition in %q: %w",
				diskPath, err)
		}
		log.Infof("Installed local EVE live image template: CONFIG partition at "+
			"offset %d, length %d", part.Offset, part.Length)
		return part, nil
	}
}
