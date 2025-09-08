// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

const (
	// EvePlatformFile contains the platform string that indicates evaluation mode
	EvePlatformFile = "/hostfs/etc/eve-platform"
	// EvaluationPlatformString is the string that must be present to indicate evaluation mode
	EvaluationPlatformString = "evaluation"
)

// IsEvaluationPlatform reads /etc/eve-platform and returns true if it contains "evaluation"
func IsEvaluationPlatform() bool {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "utils", 0)

	content, err := os.ReadFile(EvePlatformFile)
	if err != nil {
		// If file doesn't exist or can't be read, not an evaluation platform
		log.Noticef("IsEvaluationPlatform: %s not found or unreadable: %v - not evaluation platform", EvePlatformFile, err)
		return false
	}

	platformStr := strings.TrimSpace(string(content))
	isEval := strings.Contains(platformStr, EvaluationPlatformString)
	log.Noticef("IsEvaluationPlatform: platform='%s' contains '%s': %t", platformStr, EvaluationPlatformString, isEval)
	return isEval
}
