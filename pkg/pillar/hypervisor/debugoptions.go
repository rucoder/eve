// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"maps"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// debugOptions are the console's debug options as domainmgr last saw them.
// Domains are set up on their own goroutines, hence the lock.
var debugOptions struct {
	sync.Mutex
	values types.DebugOptionValues
}

// SetDebugOptions hands the hypervisor the debug options set from the local
// console (types.DebugOptionValues). Only domains started afterwards see the
// change. nil means none are set, so every option takes its default.
func SetDebugOptions(values map[string]string) {
	debugOptions.Lock()
	defer debugOptions.Unlock()
	debugOptions.values = types.DebugOptionValues{Values: maps.Clone(values)}
}

// currentDebugOptions is a snapshot for setting up one domain.
func currentDebugOptions() types.DebugOptionValues {
	debugOptions.Lock()
	defer debugOptions.Unlock()
	return debugOptions.values
}
