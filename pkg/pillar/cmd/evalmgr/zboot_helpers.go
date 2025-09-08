// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// getPartitionStates retrieves partition states for IMGA, IMGB, and IMGC
// Note: Current zboot implementation may only support IMGA/IMGB
func (ctx *evalMgrContext) getPartitionStates() (map[types.SlotName]string, error) {
	states := make(map[types.SlotName]string)

	// Get states for all supported slots
	for _, slot := range types.AllSlots() {
		switch slot {
		case types.SlotIMGA, types.SlotIMGB:
			// These are supported by current zboot implementation
			state := zboot.GetPartitionState(string(slot))
			states[slot] = state
			log.Functionf("Slot %s partition state: %s", slot, state)

		case types.SlotIMGC:
			// IMGC support depends on platform - may not be available
			// For evaluation platforms that support 3 partitions, this would work
			// For now, we attempt to get the state but handle errors gracefully
			state := zboot.GetPartitionState(string(slot))
			states[slot] = state
			log.Functionf("Slot %s partition state: %s", slot, state)

		default:
			// Unknown slot
			states[slot] = "unknown"
			log.Warnf("Unknown slot %s, marking as unknown state", slot)
		}
	}

	return states, nil
}

// setPartitionState sets the partition state for a given slot
func (ctx *evalMgrContext) setPartitionState(slot types.SlotName, state string) error {
	log.Functionf("Setting slot %s to state %s", slot, state)

	switch slot {
	case types.SlotIMGA, types.SlotIMGB:
		// Use existing zboot functions for IMGA/IMGB
		switch state {
		case "unused":
			if slot == types.SlotIMGA {
				if string(slot) == zboot.GetCurrentPartition() {
					return fmt.Errorf("cannot mark current partition %s as unused", slot)
				}
				if string(slot) == zboot.GetOtherPartition() {
					zboot.SetOtherPartitionStateUnused(log)
				}
			} else if slot == types.SlotIMGB {
				if string(slot) == zboot.GetCurrentPartition() {
					return fmt.Errorf("cannot mark current partition %s as unused", slot)
				}
				if string(slot) == zboot.GetOtherPartition() {
					zboot.SetOtherPartitionStateUnused(log)
				}
			}
		case "updating":
			if string(slot) == zboot.GetOtherPartition() {
				zboot.SetOtherPartitionStateUpdating(log)
			}
		default:
			return fmt.Errorf("unsupported state %s for slot %s", state, slot)
		}
		// Note: "testing" and "active" states are typically managed by zboot internally

	case types.SlotIMGC:
		// For IMGC, we would need extended zboot API
		// This is a platform-specific limitation
		log.Warnf("Setting state for slot %s not fully supported by current zboot API", slot)
		return fmt.Errorf("slot %s state management not supported", slot)

	default:
		return fmt.Errorf("unknown slot %s", slot)
	}

	log.Functionf("Successfully set slot %s to state %s", slot, state)
	return nil
}

// isSlotBootable checks if a slot can be booted from
func (ctx *evalMgrContext) isSlotBootable(slot types.SlotName) bool {
	switch slot {
	case types.SlotIMGA, types.SlotIMGB:
		// These are standard EVE slots
		return true
	case types.SlotIMGC:
		// IMGC availability depends on platform
		// For evaluation platforms, this should be true
		return true
	default:
		return false
	}
}

// getCurrentSlotState returns the partition state of the currently running slot
func (ctx *evalMgrContext) getCurrentSlotState() string {
	return zboot.GetPartitionState(string(ctx.currentSlot))
}

// getOtherSlots returns all slots except the current one
func (ctx *evalMgrContext) getOtherSlots() []types.SlotName {
	var others []types.SlotName
	for _, slot := range types.AllSlots() {
		if slot != ctx.currentSlot {
			others = append(others, slot)
		}
	}
	return others
}

// findSlotsInState returns all slots that are currently in the specified state
func (ctx *evalMgrContext) findSlotsInState(targetState string) ([]types.SlotName, error) {
	states, err := ctx.getPartitionStates()
	if err != nil {
		return nil, fmt.Errorf("failed to get partition states: %w", err)
	}

	var matches []types.SlotName
	for slot, state := range states {
		if state == targetState {
			matches = append(matches, slot)
		}
	}

	return matches, nil
}

// validatePartitionStates checks for inconsistent partition states
func (ctx *evalMgrContext) validatePartitionStates() []string {
	var issues []string

	states, err := ctx.getPartitionStates()
	if err != nil {
		issues = append(issues, fmt.Sprintf("failed to get partition states: %v", err))
		return issues
	}

	// Check for multiple testing partitions
	testingSlots := make([]types.SlotName, 0)
	activeSlots := make([]types.SlotName, 0)

	for slot, state := range states {
		switch state {
		case "testing":
			testingSlots = append(testingSlots, slot)
		case "active":
			activeSlots = append(activeSlots, slot)
		}
	}

	if len(testingSlots) > 1 {
		issues = append(issues, fmt.Sprintf("multiple slots in testing state: %v", testingSlots))
	}

	if len(activeSlots) > 1 {
		issues = append(issues, fmt.Sprintf("multiple slots in active state: %v", activeSlots))
	}

	// Check if current slot has expected state
	currentState := states[ctx.currentSlot]
	if currentState != "active" && currentState != "inprogress" && currentState != "testing" {
		issues = append(issues, fmt.Sprintf("current slot %s has unexpected state: %s", ctx.currentSlot, currentState))
	}

	return issues
}

// logZbootDiagnostics logs detailed zboot state information for troubleshooting
func (ctx *evalMgrContext) logZbootDiagnostics() {
	log.Functionf("=== ZBOOT DIAGNOSTICS ===")

	// Current partition info
	current := zboot.GetCurrentPartition()
	log.Functionf("zboot current partition: %s", current)

	// Other partition (for 2-partition systems)
	if current == "IMGA" || current == "IMGB" {
		other := zboot.GetOtherPartition()
		log.Functionf("zboot other partition: %s", other)
	}

	// Partition states
	states, err := ctx.getPartitionStates()
	if err != nil {
		log.Errorf("Failed to get partition states: %v", err)
	} else {
		for slot, state := range states {
			log.Functionf("zboot partition %s state: %s", slot, state)
		}
	}

	// Validation issues
	issues := ctx.validatePartitionStates()
	if len(issues) > 0 {
		log.Warnf("Partition state issues detected:")
		for _, issue := range issues {
			log.Warnf("  - %s", issue)
		}
	} else {
		log.Functionf("No partition state issues detected")
	}

	log.Functionf("========================")
}
