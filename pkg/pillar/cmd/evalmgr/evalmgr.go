// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

const (
	// AllowOnboardOverrideFile allows manual override of onboarding gate
	AllowOnboardOverrideFile = "/persist/eval/allow_onboard"
)

// initializeEvaluation performs initial evaluation setup
func (ctx *evalMgrContext) initializeEvaluation() error {
	log.Functionf("initializeEvaluation starting")

	// Detect if this is an evaluation platform
	ctx.isEvaluationPlatform = utils.IsEvaluationPlatform()
	log.Noticef("Evaluation platform detection: isEvaluationPlatform=%t", ctx.isEvaluationPlatform)

	// Get current partition
	currentPartStr := zboot.GetCurrentPartition()
	ctx.currentSlot = types.SlotName(currentPartStr)
	log.Noticef("Current partition: %s", ctx.currentSlot)

	// Phase 2: Perform partition state reconciliation on evaluation platforms
	if ctx.isEvaluationPlatform {
		log.Functionf("Performing partition state reconciliation")

		// Log current partition states for diagnostics
		ctx.logZbootDiagnostics()

		// Validate current slot state
		if err := ctx.validateCurrentSlotState(); err != nil {
			log.Errorf("Current slot validation failed: %v", err)
		}

		// Reconcile partition states (detect and clean up failed boots)
		if err := ctx.reconcilePartitionStates(); err != nil {
			log.Errorf("Partition reconciliation failed: %v", err)
			// Continue with initialization even if reconciliation fails
		}
	}

	// Initialize evaluation status
	allowOnboard := ctx.shouldAllowOnboard()
	statusNote := ctx.generateStatusNote()

	log.Noticef("initializeEvaluation: key decisions - platform=%t, slot=%s, allowOnboard=%t",
		ctx.isEvaluationPlatform, ctx.currentSlot, allowOnboard)
	log.Noticef("initializeEvaluation: status note: %s", statusNote)

	ctx.evalStatus = types.EvalStatus{
		IsEvaluationPlatform: ctx.isEvaluationPlatform,
		CurrentSlot:          ctx.currentSlot,
		Phase:                types.EvalPhaseInit,
		AllowOnboard:         allowOnboard,
		Note:                 statusNote,
		LastUpdated:          time.Now(),
	}

	// Perform fault injection if configured
	if ctx.isEvaluationPlatform {
		if err := ctx.performFaultInjection(); err != nil {
			log.Errorf("Fault injection failed: %v", err)
			// Don't fail initialization due to fault injection errors
		}
	}

	log.Functionf("initializeEvaluation completed")
	return nil
}

// shouldAllowOnboard determines if onboarding should be allowed
func (ctx *evalMgrContext) shouldAllowOnboard() bool {
	// If not an evaluation platform, always allow onboarding
	if !ctx.isEvaluationPlatform {
		log.Noticef("shouldAllowOnboard: not evaluation platform - allowing onboarding")
		return true
	}

	// Check for manual override file
	if ctx.hasOnboardOverride() {
		log.Noticef("shouldAllowOnboard: manual override file present - allowing onboarding")
		return true
	}

	// Check scheduler state - only allow onboarding when evaluation is finalized
	switch ctx.schedulerState {
	case SchedulerFinalized:
		// Evaluation complete - allow onboarding
		log.Noticef("shouldAllowOnboard: scheduler finalized - allowing onboarding")
		return true
	case SchedulerIdle, SchedulerStabilityWait, SchedulerScheduled:
		// Evaluation still in progress - block onboarding
		log.Noticef("shouldAllowOnboard: scheduler state %v - blocking onboarding", ctx.schedulerState)
		return false
	default:
		// Unknown state - be conservative
		log.Warnf("shouldAllowOnboard: unknown scheduler state %v - blocking onboarding", ctx.schedulerState)
		return false
	}
}

// hasOnboardOverride checks if manual onboard override is set
func (ctx *evalMgrContext) hasOnboardOverride() bool {
	content, err := os.ReadFile(AllowOnboardOverrideFile)
	if err != nil {
		log.Functionf("hasOnboardOverride: %s not found or unreadable: %v", AllowOnboardOverrideFile, err)
		return false
	}

	value := strings.TrimSpace(string(content))
	result := value == "1" || strings.ToLower(value) == "true" || strings.ToLower(value) == "yes"
	log.Noticef("hasOnboardOverride: file content='%s' -> override=%t", value, result)
	return result
}

// generateStatusNote creates a human-readable status note
func (ctx *evalMgrContext) generateStatusNote() string {
	if !ctx.isEvaluationPlatform {
		return "Normal platform, evaluation disabled"
	}

	var notes []string
	notes = append(notes, fmt.Sprintf("Slot %s", ctx.currentSlot))

	// Add current partition state info
	currentState := ctx.getCurrentSlotState()
	notes = append(notes, fmt.Sprintf("state=%s", currentState))

	// Add scheduler state information
	switch ctx.schedulerState {
	case SchedulerIdle:
		notes = append(notes, "scheduler idle")
	case SchedulerStabilityWait:
		if !ctx.stabilityStartTime.IsZero() {
			elapsed := time.Since(ctx.stabilityStartTime)
			notes = append(notes, fmt.Sprintf("stability check (%v)", elapsed.Truncate(time.Second)))
		} else {
			notes = append(notes, "stability check")
		}
	case SchedulerScheduled:
		notes = append(notes, "next slot scheduled")
	case SchedulerFinalized:
		notes = append(notes, "evaluation complete")
	}

	if ctx.shouldAllowOnboard() {
		notes = append(notes, "onboard allowed")
	} else {
		notes = append(notes, "onboard blocked")
	}

	return strings.Join(notes, ", ")
}

// publishEvalStatus publishes the current evaluation status
func (ctx *evalMgrContext) publishEvalStatus() {
	log.Functionf("Publishing EvalStatus: phase=%s, slot=%s, allowOnboard=%t",
		ctx.evalStatus.Phase, ctx.evalStatus.CurrentSlot, ctx.evalStatus.AllowOnboard)

	if err := ctx.pubEvalStatus.Publish(ctx.evalStatus.Key(), ctx.evalStatus); err != nil {
		log.Errorf("Failed to publish EvalStatus: %v", err)
	} else {
		log.Noticef("Published EvalStatus: %s", ctx.evalStatus.DetailedNote())
	}
}

// updateEvalStatus updates and publishes evaluation status
func (ctx *evalMgrContext) updateEvalStatus() {
	oldStatus := ctx.evalStatus

	// Update fields that might have changed
	ctx.evalStatus.AllowOnboard = ctx.shouldAllowOnboard()
	ctx.evalStatus.Note = ctx.generateStatusNote()
	ctx.evalStatus.LastUpdated = time.Now()

	// Only publish if something actually changed
	if oldStatus.AllowOnboard != ctx.evalStatus.AllowOnboard ||
		oldStatus.Note != ctx.evalStatus.Note ||
		oldStatus.Phase != ctx.evalStatus.Phase {
		ctx.publishEvalStatus()
	}
}
