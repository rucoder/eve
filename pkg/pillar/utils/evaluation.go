// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"os"
	"strings"
)

const (
	// EvaluationPlatformFile contains the platform string that indicates evaluation mode
	EvaluationPlatformFile = "/etc/eve-platform"
	// EvaluationPlatformString is the string that must be present to indicate evaluation mode
	EvaluationPlatformString = "evaluation"
)

// IsEvaluationPlatform reads /etc/eve-platform and returns true if it contains "evaluation"
func IsEvaluationPlatform() bool {
	content, err := os.ReadFile(EvaluationPlatformFile)
	if err != nil {
		// If file doesn't exist or can't be read, not an evaluation platform
		return false
	}

	platformStr := strings.TrimSpace(string(content))
	return strings.Contains(platformStr, EvaluationPlatformString)
}
