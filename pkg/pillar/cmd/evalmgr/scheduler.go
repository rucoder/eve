// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

const (
	// DefaultStabilityPeriod is how long we wait to consider a slot stable
	DefaultStabilityPeriod = 5 * time.Minute
	// RebootReasonEvalNextSlot is the reason we write when switching to next slot
	RebootReasonEvalNextSlot = "evaluation-next-slot"
	// RebootReasonEvalFinalize is the reason when switching to best slot
	RebootReasonEvalFinalize = "evaluation-finalize"
)

// SchedulerState tracks the current scheduling state
type SchedulerState int

const (
	// SchedulerIdle - no active scheduling
	SchedulerIdle SchedulerState = iota
	// SchedulerStabilityWait - waiting for current slot to prove stable
	SchedulerStabilityWait
	// SchedulerScheduled - next slot scheduled, waiting for reboot
	SchedulerScheduled
	// SchedulerFinalized - evaluation complete, best slot selected
	SchedulerFinalized
)

// initializeScheduler sets up the scheduling system
func (ctx *evalMgrContext) initializeScheduler() error {
	log.Functionf("initializeScheduler starting")

	// Analyze previous boot to understand what happened
	ctx.analyzePreviousBoot()

	// Load persistent state to understand where we are in evaluation
	state, err := ctx.loadEvalState()
	if err != nil {
		log.Errorf("Failed to load eval state: %v", err)
		state = ctx.createDefaultEvalState()
	}

	// Check if current slot needs promotion from active/updating to testing
	ctx.promoteCurrentSlotIfNeeded(state)

	// Determine current scheduling state
	ctx.updateSchedulingState(state)

	// Start stability timer if needed
	if ctx.shouldStartStabilityTimer(state) {
		ctx.startStabilityTimer()
	}

	log.Functionf("initializeScheduler completed")
	return nil
}

// analyzePreviousBoot examines the previous reboot reason and updates slot states accordingly
func (ctx *evalMgrContext) analyzePreviousBoot() error {
	prevReason, prevTime, prevStack := agentlog.GetRebootReason(log)
	if prevReason == "" {
		log.Functionf("No previous reboot reason found")
		return nil
	}

	log.Noticef("Previous reboot reason: %s at %s", prevReason, prevTime.Format(time.RFC3339))

	// Load current state to update
	state, err := ctx.loadEvalState()
	if err != nil {
		log.Errorf("Failed to load state for previous boot analysis: %v", err)
		return err
	}

	// Analyze the reboot reason
	analysis := ctx.classifyRebootReason(prevReason, prevStack)
	log.Noticef("Reboot analysis: planned=%t, successful=%t, reason=%s",
		analysis.WasPlanned, analysis.WasSuccessful, analysis.Classification)

	// Update slot states based on analysis
	if analysis.WasPlanned {
		// This was a planned evaluation reboot
		if analysis.TargetSlot != "" && analysis.TargetSlot != ctx.currentSlot {
			// We were switching to a different slot, but we're not running it
			// This means the target slot failed to boot
			log.Errorf("Planned switch to slot %s failed, now running %s",
				analysis.TargetSlot, ctx.currentSlot)
			ctx.updateSlotState(state, analysis.TargetSlot, true, false,
				"Boot failed - fallback to "+string(ctx.currentSlot))
		} else {
			// Successful planned reboot to current slot
			log.Noticef("Successful planned reboot to slot %s", ctx.currentSlot)
		}
	} else {
		// Unplanned reboot - current slot may be unstable
		if !analysis.WasSuccessful {
			log.Errorf("Unplanned reboot detected: %s", analysis.Classification)
			// Don't immediately mark as failed - wait for stability period
			// But note the concerning reboot reason
			currentState := ctx.getSlotState(state, ctx.currentSlot)
			currentState.Note = fmt.Sprintf("Unplanned reboot: %s", analysis.Classification)
			state.Slots[ctx.currentSlot] = currentState
		}
	}

	// Save updated state
	if err := ctx.saveEvalState(state); err != nil {
		log.Errorf("Failed to save state after boot analysis: %v", err)
	}

	// Clear the reboot reason since we've processed it
	agentlog.DiscardRebootReason(log)
	return nil
}

// BootAnalysis contains the analysis of a reboot reason
type BootAnalysis struct {
	WasPlanned     bool
	WasSuccessful  bool
	Classification string
	TargetSlot     types.SlotName
}

// classifyRebootReason analyzes a reboot reason to understand what happened
func (ctx *evalMgrContext) classifyRebootReason(reason, stack string) BootAnalysis {
	analysis := BootAnalysis{
		WasPlanned:     false,
		WasSuccessful:  true,
		Classification: "unknown",
	}

	reasonLower := strings.ToLower(reason)

	// Check for planned evaluation reboots
	if strings.Contains(reason, RebootReasonEvalNextSlot) {
		analysis.WasPlanned = true
		analysis.Classification = "planned evaluation slot switch"
		// Extract target slot from reason
		if strings.Contains(reason, "IMGA") {
			analysis.TargetSlot = types.SlotIMGA
		} else if strings.Contains(reason, "IMGB") {
			analysis.TargetSlot = types.SlotIMGB
		} else if strings.Contains(reason, "IMGC") {
			analysis.TargetSlot = types.SlotIMGC
		}
		return analysis
	}

	if strings.Contains(reason, RebootReasonEvalFinalize) {
		analysis.WasPlanned = true
		analysis.Classification = "planned evaluation finalization"
		return analysis
	}

	// Check for problematic reboots
	if strings.Contains(reasonLower, "watchdog") {
		analysis.WasSuccessful = false
		analysis.Classification = "watchdog timeout"
		return analysis
	}

	if strings.Contains(reasonLower, "kernel panic") || strings.Contains(reasonLower, "panic") {
		analysis.WasSuccessful = false
		analysis.Classification = "kernel panic"
		return analysis
	}

	if strings.Contains(reasonLower, "fatal") {
		analysis.WasSuccessful = false
		analysis.Classification = "fatal error"
		return analysis
	}

	// Check for power-related issues
	if strings.Contains(reasonLower, "power") {
		analysis.Classification = "power failure"
		// Power failure is not necessarily a slot failure
		return analysis
	}

	// Normal planned reboots
	if strings.Contains(reasonLower, "user") || strings.Contains(reasonLower, "requested") {
		analysis.WasPlanned = true
		analysis.Classification = "user requested"
		return analysis
	}

	if strings.Contains(reasonLower, "baseos") || strings.Contains(reasonLower, "update") {
		analysis.WasPlanned = true
		analysis.Classification = "baseos update"
		return analysis
	}

	// Default classification
	analysis.Classification = "unclassified reboot"
	return analysis
}

// updateSchedulingState determines what state the scheduler should be in
func (ctx *evalMgrContext) updateSchedulingState(state *types.EvalPersist) {
	// Check if current slot needs stability validation FIRST
	currentState := ctx.getSlotState(state, ctx.currentSlot)
	if !currentState.Success && currentState.Tried {
		// Current slot was tried but not yet marked successful
		ctx.schedulerState = SchedulerStabilityWait
		log.Noticef("Current slot %s needs stability validation", ctx.currentSlot)
		return
	}

	// Check if all slots have been tried
	allTried := true
	for _, slot := range types.AllSlots() {
		slotState := ctx.getSlotState(state, slot)
		if !slotState.Tried {
			allTried = false
			break
		}
	}

	if allTried {
		ctx.schedulerState = SchedulerFinalized
		log.Noticef("All slots have been tried - evaluation ready for finalization")
		return
	}

	// Default to idle - we'll start stability timer if needed
	ctx.schedulerState = SchedulerIdle
}

// shouldStartStabilityTimer determines if we should start the stability timer
func (ctx *evalMgrContext) shouldStartStabilityTimer(state *types.EvalPersist) bool {
	if ctx.schedulerState != SchedulerStabilityWait {
		return false
	}

	currentState := ctx.getSlotState(state, ctx.currentSlot)
	// Start timer if current slot is tried but not yet successful
	return currentState.Tried && !currentState.Success
}

// startStabilityTimer begins the stability validation period
func (ctx *evalMgrContext) startStabilityTimer() {
	stabilityPeriod := DefaultStabilityPeriod
	// TODO: Make configurable via GlobalConfig

	log.Noticef("Starting stability timer for slot %s (period: %v)", ctx.currentSlot, stabilityPeriod)

	// Stop any existing timer
	if ctx.stabilityTimer != nil {
		ctx.stabilityTimer.Stop()
	}

	// Set phase to testing so timing info appears in diag
	ctx.evalStatus.Phase = types.EvalPhaseTesting
	ctx.evalStatus.TestStartTime = time.Now()
	ctx.evalStatus.TestDuration = stabilityPeriod

	ctx.stabilityTimer = time.NewTimer(stabilityPeriod)
	ctx.stabilityStartTime = time.Now()
}

// handleStabilityTimeout is called when the stability timer expires
func (ctx *evalMgrContext) handleStabilityTimeout() {
	log.Noticef("Stability period completed for slot %s", ctx.currentSlot)

	// Load current state
	state, err := ctx.loadEvalState()
	if err != nil {
		log.Errorf("Failed to load state for stability timeout: %v", err)
		return
	}

	// Mark current slot as successful
	ctx.updateSlotState(state, ctx.currentSlot, true, true,
		fmt.Sprintf("Stable for %v", DefaultStabilityPeriod))

	// Promote current slot from testing to active if needed
	// Check if current slot needs promotion from inprogress to active after stability
	currentPartitionState := zboot.GetPartitionState(string(ctx.currentSlot))
	if currentPartitionState == "inprogress" {
		log.Noticef("Promoting slot %s from inprogress to active after stability validation", ctx.currentSlot)
		// Use standard zboot function to set current partition to active
		zboot.SetPartitionState(log, string(ctx.currentSlot), "active")
		log.Noticef("Successfully promoted slot %s to active", ctx.currentSlot)
	}

	// Save state
	if err := ctx.saveEvalState(state); err != nil {
		log.Errorf("Failed to save state after stability validation: %v", err)
		return
	}

	// Update scheduling state and consider next slot
	ctx.schedulerState = SchedulerIdle
	ctx.scheduleNextSlotIfNeeded(state)

	// Update and publish status
	ctx.updateEvalStatus()
}

// scheduleNextSlotIfNeeded finds and schedules the next untried slot
func (ctx *evalMgrContext) scheduleNextSlotIfNeeded(state *types.EvalPersist) {
	nextSlot := ctx.findNextUntriedSlot(state)
	if nextSlot == types.SlotFinal {
		log.Noticef("No more untried slots - evaluation complete")
		ctx.schedulerState = SchedulerFinalized
		ctx.finalizeEvaluation(state)
		return
	}

	log.Noticef("Scheduling next slot for testing: %s", nextSlot)

	// Mark next slot as tried
	ctx.updateSlotState(state, nextSlot, true, false, "Scheduled for testing")

	// Save state before reboot
	if err := ctx.saveEvalState(state); err != nil {
		log.Errorf("Failed to save state before scheduling: %v", err)
		return
	}

	// Set next partition to updating state for reboot (grub will auto-transition to inprogress)
	log.Noticef("Setting slot %s to updating state for reboot", nextSlot)
	zboot.SetPartitionState(log, string(nextSlot), "updating")

	ctx.schedulerState = SchedulerScheduled

	// Request reboot via nodeagent
	reasonStr := RebootReasonEvalNextSlot + "-" + string(nextSlot)
	if err := ctx.requestReboot(reasonStr); err != nil {
		log.Errorf("Failed to request reboot: %v", err)
		return
	}
	log.Noticef("Requested reboot to test slot %s", nextSlot)
}

// findNextUntriedSlot returns the next slot that hasn't been tried yet
func (ctx *evalMgrContext) findNextUntriedSlot(state *types.EvalPersist) types.SlotName {
	if !ctx.isEvaluationPlatform {
		// For non-evaluation platforms, use simple logic
		for _, slot := range types.AllSlots() {
			if slot == ctx.currentSlot {
				continue // Skip current slot
			}
			slotState := ctx.getSlotState(state, slot)
			if !slotState.Tried {
				return slot
			}
		}
		return types.SlotFinal
	}

	// For evaluation platforms, use simple loop-based partition selection
	triedSlots := make(map[string]bool)
	for _, slot := range types.AllSlots() {
		slotState := ctx.getSlotState(state, slot)
		triedSlots[string(slot)] = slotState.Tried
	}

	// Use simple loop partition selection - returns FINAL if no partitions left
	nextPartition := zboot.GetNextEvaluationPartition(string(ctx.currentSlot), triedSlots)
	if nextPartition == "FINAL" {
		return types.SlotFinal
	}
	return types.SlotName(nextPartition)
}

// promoteCurrentSlotIfNeeded promotes current slot from active/updating to testing if needed
func (ctx *evalMgrContext) promoteCurrentSlotIfNeeded(state *types.EvalPersist) {
	currentPartitionState := zboot.GetPartitionState(string(ctx.currentSlot))

	switch currentPartitionState {
	case "active":
		// First time after installation or previous successful evaluation - start new evaluation
		log.Noticef("Current slot %s is active - starting evaluation", ctx.currentSlot)

	case "updating":
		// We rebooted into an updating slot - grub will auto-transition to inprogress
		log.Noticef("Current slot %s is updating - will auto-transition to inprogress", ctx.currentSlot)

	case "inprogress":
		// We rebooted into an inprogress slot - this means we're testing it
		log.Noticef("Current slot %s is inprogress - continuing evaluation", ctx.currentSlot)

	default:
		log.Warnf("Current slot %s has unexpected state %s", ctx.currentSlot, currentPartitionState)
	}
}

// finalizeEvaluation selects the best slot and finalizes evaluation
func (ctx *evalMgrContext) finalizeEvaluation(state *types.EvalPersist) {
	log.Noticef("Finalizing evaluation - selecting best slot")

	// TODO: Implement inventory collection for scoring
	inventories := make(map[types.SlotName]InventoryData)

	bestSlot := ctx.selectBestSlot(state, inventories)
	log.Noticef("Selected best slot: %s", bestSlot)

	// Update state
	state.BestSlot = bestSlot
	state.Phase = types.EvalPhaseFinal

	if bestSlot != ctx.currentSlot {
		log.Noticef("Best slot %s differs from current %s - scheduling switch", bestSlot, ctx.currentSlot)

		// Set best slot as active
		zboot.SetPartitionState(log, string(bestSlot), "active")

		// Mark others as unused
		for _, slot := range types.AllSlots() {
			if slot != bestSlot {
				zboot.SetPartitionState(log, string(slot), "unused")
			}
		}

		// Request reboot to best slot
		reasonStr := RebootReasonEvalFinalize + "-" + string(bestSlot)
		if err := ctx.requestReboot(reasonStr); err != nil {
			log.Errorf("Failed to request reboot to best slot: %v", err)
			return
		}
		log.Noticef("Requested reboot to best slot %s", bestSlot)
	} else {
		log.Noticef("Already running best slot %s - evaluation complete", bestSlot)
		// Update allow onboard since we're finalized
		ctx.evalStatus.Phase = types.EvalPhaseFinal
		ctx.evalStatus.AllowOnboard = true
		ctx.evalStatus.Note = fmt.Sprintf("Evaluation complete - running best slot %s", bestSlot)
	}

	// Save final state
	if err := ctx.saveEvalState(state); err != nil {
		log.Errorf("Failed to save final evaluation state: %v", err)
	}
}

// InventoryData represents hardware inventory for a slot (placeholder)
type InventoryData struct {
	CPUCount   int
	MemoryMB   int
	DiskCount  int
	NICCount   int
	PCIDevices int
	// TODO: Add more inventory fields
}

// selectBestSlot chooses the best slot based on success and inventory
func (ctx *evalMgrContext) selectBestSlot(state *types.EvalPersist, inventories map[types.SlotName]InventoryData) types.SlotName {
	// TODO: Implement configurable scoring algorithm
	// Priority:
	// 1. Successful slots only
	// 2. Biggest HW inventory (more hardware detected = better)
	// 3. Tie-breaker: "least letter" slot (A > B > C)
	// 4. If inventory sizes equal: prefer earlier slot

	var bestSlot types.SlotName
	var bestScore int

	for _, slot := range types.AllSlots() {
		slotState := ctx.getSlotState(state, slot)
		if !slotState.Success {
			continue // Only consider successful slots
		}

		// Calculate basic score (placeholder algorithm)
		score := 0
		inventory, hasInventory := inventories[slot]
		if hasInventory {
			score = inventory.CPUCount + inventory.DiskCount + inventory.NICCount + inventory.PCIDevices
		}

		// Tie-breaker: prefer earlier slots (A=3, B=2, C=1)
		switch slot {
		case types.SlotIMGA:
			score += 3
		case types.SlotIMGB:
			score += 2
		case types.SlotIMGC:
			score += 1
		}

		if bestSlot == "" || score > bestScore {
			bestSlot = slot
			bestScore = score
		}

		log.Functionf("Slot %s score: %d (success=%t)", slot, score, slotState.Success)
	}

	// Fallback to current slot if no successful slots found
	if bestSlot == "" {
		log.Warnf("No successful slots found - defaulting to current slot %s", ctx.currentSlot)
		bestSlot = ctx.currentSlot
	}

	return bestSlot
}

// requestReboot requests a system reboot with the given reason after a countdown
func (ctx *evalMgrContext) requestReboot(reason string) error {
	log.Noticef("Scheduling reboot in 15 seconds: %s", reason)

	// Start 15-second countdown
	ctx.rebootCountdown = 15
	ctx.evalStatus.Note = "Rebooting: " + reason

	// Store the reboot reason for later use in executeReboot
	ctx.scheduledRebootReason = reason

	// Update status immediately to show countdown
	ctx.updateTimingFields()
	ctx.publishEvalStatus()

	return nil
}

// executeReboot performs the actual reboot when countdown expires
func (ctx *evalMgrContext) executeReboot() error {
	log.Noticef("Executing direct reboot (nodeagent may not be active before onboarding)")

	// Save reboot reason before rebooting (nodeagent is not available pre-onboarding)
	agentlog.RebootReason(ctx.scheduledRebootReason, types.BootReasonRebootCmd, "evalmgr", os.Getpid(), true)

	// Sync filesystems before reboot
	log.Noticef("Syncing filesystems before reboot")
	syscall.Sync()

	// Direct reboot via zboot (same as nodeagent would do)
	log.Noticef("Calling zboot.Reset() for reboot, reason: %s", ctx.scheduledRebootReason)
	zboot.Reset(log)

	// Should not reach here
	return fmt.Errorf("zboot.Reset() returned unexpectedly")
}
