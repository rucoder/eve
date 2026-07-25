// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// refSanitizer mirrors `tr '/:' '__'` applied by the build when it
// names images inside the OCI layout (pkg/kube-images/Dockerfile).
var refSanitizer = strings.NewReplacer("/", "_", ":", "_")

// sanitizeRef converts a real registry ref to the sanitized OCI
// ref-name the build assigns in the layout.
func sanitizeRef(realRef string) string { return refSanitizer.Replace(realRef) }

// loadRefMap reads the shipped ref list (one real ref per line) and
// returns sanitized -> real. A missing catalog is not an error: layouts
// such as the external-boot-image erofs ship no catalog at all, and
// their single image resolves via the eve-external-boot-image special
// case instead.
func loadRefMap(listPath string) (map[string]string, error) {
	f, err := os.Open(listPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", listPath, err)
	}
	defer func() { _ = f.Close() }()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ref := strings.TrimSpace(sc.Text())
		if ref == "" {
			continue
		}
		m[sanitizeRef(ref)] = ref
	}
	return m, sc.Err()
}
