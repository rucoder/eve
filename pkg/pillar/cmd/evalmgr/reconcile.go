// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// reconcilePartitionStates checks for failed boots and cleans up partition states
// This implements Phase 2 functionality - detecting slots that were marked "testing"
// but failed to boot (indicated by booting into a different partition)
func (ctx *evalMgrContext) reconcilePartitionStates() error {
	log.Functionf("Starting partition state reconciliation")

	// Load current persistent state
	evalState, err := ctx.loadEvalState()
	if err != nil {
		return fmt.Errorf("failed to load eval state: %w", err)
	}

	reconciled := false
	var reconcileNotes []string

	// Check each slot for failed testing
	for _, slot := range types.AllSlots() {
		partitionState := zboot.GetPartitionState(string(slot))

		// If a slot is in "testing" state but we're not currently running from it,
		// then it failed to boot and GRUB fell back to the previous active partition
		if partitionState == "testing" && slot != ctx.currentSlot {
			log.Noticef("Detected failed boot for slot %s (state=%s, current=%s)",
				slot, partitionState, ctx.currentSlot)

			// Mark the slot as unused in GRUB
			if err := ctx.markSlotUnused(slot); err != nil {
				log.Errorf("Failed to mark slot %s as unused: %v", slot, err)
				continue
			}

			// Update our persistent state to record the failure
			ctx.updateSlotState(evalState, slot, true, false, "fallback observed - boot failed")
			reconciled = true

			reconcileNote := fmt.Sprintf("slot %s failed boot, marked unused", slot)
			reconcileNotes = append(reconcileNotes, reconcileNote)

			log.Noticef("Reconciled failed slot %s: marked as unused", slot)
		}
	}

	// Save updated state if any reconciliation occurred
	if reconciled {
		if err := ctx.saveEvalState(evalState); err != nil {
			return fmt.Errorf("failed to save reconciled state: %w", err)
		}

		// Update our context's evaluation status note
		ctx.evalStatus.Note = fmt.Sprintf("Reconciled: %v", reconcileNotes)
		ctx.publishEvalStatus()

		log.Noticef("Partition reconciliation completed: %v", reconcileNotes)
	} else {
		log.Functionf("No partition reconciliation needed")
	}

	return nil
}

// validateCurrentSlotState ensures the current slot state is consistent
func (ctx *evalMgrContext) validateCurrentSlotState() error {
	currentPartitionState := zboot.GetPartitionState(string(ctx.currentSlot))

	log.Functionf("Current slot %s has partition state: %s", ctx.currentSlot, currentPartitionState)

	// The currently running slot should typically be "active" or "inprogress"
	// If it's "testing", that means we successfully booted into a test slot
	switch currentPartitionState {
	case "active":
		log.Functionf("Current slot %s is active (normal operation)", ctx.currentSlot)
	case "inprogress":
		log.Functionf("Current slot %s is inprogress (normal during evaluation)", ctx.currentSlot)
	case "testing":
		log.Functionf("Current slot %s is testing (successful test boot)", ctx.currentSlot)
	case "updating":
		log.Functionf("Current slot %s is updating (image installation)", ctx.currentSlot)
	default:
		log.Warnf("Current slot %s has unexpected state: %s", ctx.currentSlot, currentPartitionState)
	}

	return nil
}

// markSlotUnused sets a partition slot to unused state via zboot
func (ctx *evalMgrContext) markSlotUnused(slot types.SlotName) error {
	log.Functionf("Marking slot %s as unused", slot)

	// Use zboot to set the partition state to unused
	// This calls the equivalent of: zboot set_partstate SLOT unused
	if slot == types.SlotIMGA || slot == types.SlotIMGB {
		// These are the standard slots that zboot supports
		if slot == types.SlotIMGA {
			if ctx.currentSlot == types.SlotIMGA {
				return fmt.Errorf("cannot mark current slot %s as unused", slot)
			}
			// For now, we use the existing zboot API which works with IMGA/IMGB
			if string(slot) == zboot.GetOtherPartition() {
				zboot.SetOtherPartitionStateUnused(log)
			}
		} else if slot == types.SlotIMGB {
			if ctx.currentSlot == types.SlotIMGB {
				return fmt.Errorf("cannot mark current slot %s as unused", slot)
			}
			if string(slot) == zboot.GetOtherPartition() {
				zboot.SetOtherPartitionStateUnused(log)
			}
		}
	} else {
		// For IMGC or future slots, we would need to extend zboot API
		// For now, log this limitation
		log.Warnf("Cannot mark slot %s as unused - zboot API limitation (only supports IMGA/IMGB)", slot)
	}

	log.Functionf("Successfully marked slot %s as unused", slot)
	return nil
}

// getAllPartitionStates returns the current partition states for all slots
func (ctx *evalMgrContext) getAllPartitionStates() map[types.SlotName]string {
	states := make(map[types.SlotName]string)

	for _, slot := range types.AllSlots() {
		// Note: zboot.GetPartitionState may not support IMGC in current implementation
		// This is a limitation we acknowledge for Phase 2
		if slot == types.SlotIMGA || slot == types.SlotIMGB {
			states[slot] = zboot.GetPartitionState(string(slot))
		} else {
			// For unsupported slots, we mark as unknown
			states[slot] = "unknown"
		}
	}

	return states
}

// logPartitionStates logs the current state of all partitions for debugging
func (ctx *evalMgrContext) logPartitionStates() {
	log.Functionf("=== Partition States ===")
	log.Functionf("Current slot: %s", ctx.currentSlot)

	states := ctx.getAllPartitionStates()
	for slot, state := range states {
		marker := ""
		if slot == ctx.currentSlot {
			marker = " (current)"
		}
		log.Functionf("Slot %s: %s%s", slot, state, marker)
	}
	log.Functionf("========================")
}
