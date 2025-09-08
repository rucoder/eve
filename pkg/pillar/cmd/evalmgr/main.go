// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"flag"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	"github.com/sirupsen/logrus"
)

const (
	agentName        = "evalmgr"
	errorTime        = 3 * time.Minute
	warningTime      = 40 * time.Second
	stillRunningTime = 25 * time.Second
)

// Set from Makefile
var Version = "No version specified"

var logger *logrus.Logger
var log *base.LogObject

type evalMgrContext struct {
	agentbase.AgentBase
	pubEvalStatus pubsub.Publication

	// CLI flags can be added here if needed

	// Current state
	isEvaluationPlatform bool
	currentSlot          types.SlotName
	evalStatus           types.EvalStatus

	// Timing and periodic updates
	statusUpdateTicker *time.Ticker
	rebootTicker       *time.Ticker
	rebootCountdown    int

	// Scheduler state
	schedulerState        SchedulerState
	stabilityTimer        *time.Timer
	scheduledRebootReason string
	stabilityStartTime    time.Time
}

var debug = false

// Run is the main entry point for evalmgr, matching types.AgentRunner signature
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	logf := func(format string, args ...interface{}) {
		log.Noticef(format, args...)
	}
	logf("Starting %s", agentName)

	// Initialize context
	ctx := evalMgrContext{}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	// Access CLI flags - debug flag provided by agentbase
	debug = ctx.CLIParams().DebugOverride

	// Initialize publications
	if err := ctx.initPubSub(ps); err != nil {
		log.Fatal(err)
	}

	// Publish preliminary status immediately to prevent client race condition
	ctx.publishPreliminaryStatus()

	// Run the main loop
	if err := ctx.run(ps); err != nil {
		log.Errorf("evalmgr run failed: %v", err)
		return 1
	}

	logf("Exiting %s", agentName)
	return 0
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *evalMgrContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
	// Debug flag is provided by agentbase automatically
	// Add custom flags here if needed
}

func (ctx *evalMgrContext) initPubSub(ps *pubsub.PubSub) error {
	var err error

	// Initialize EvalStatus publication
	ctx.pubEvalStatus, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			TopicType:  types.EvalStatus{},
			Persistent: true,
		})
	if err != nil {
		return fmt.Errorf("failed to create EvalStatus publication: %w", err)
	}

	// Note: We don't subscribe to GlobalConfig because:
	// 1. It only comes after onboarding to controller
	// 2. evalmgr needs to run BEFORE onboarding to gate it
	// 3. This creates a circular dependency

	return nil
}

func (ctx *evalMgrContext) run(ps *pubsub.PubSub) error {
	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningTime)
	defer stillRunning.Stop()

	// No need to wait for GlobalConfig - we operate independently
	log.Noticef("Starting evaluation initialization (no GlobalConfig dependency)")

	// Initialize and publish initial status
	if err := ctx.initializeEvaluation(); err != nil {
		return fmt.Errorf("failed to initialize evaluation: %w", err)
	}

	// Initialize scheduler (Phase 3)
	if err := ctx.initializeScheduler(); err != nil {
		return fmt.Errorf("failed to initialize scheduler: %w", err)
	}

	// Publish initial status
	ctx.publishEvalStatus()

	// Setup periodic status updates (every 30 seconds)
	ctx.statusUpdateTicker = time.NewTicker(30 * time.Second)
	defer ctx.statusUpdateTicker.Stop()

	// Setup reboot countdown ticker (every 1 second)
	ctx.rebootTicker = time.NewTicker(1 * time.Second)
	defer ctx.rebootTicker.Stop()

	// Start main event loop
	log.Noticef("Starting main event loop")

	for {
		select {
		case <-stillRunning.C:
			ps.StillRunning(agentName, warningTime, errorTime)

		case <-ctx.getStabilityTimerChannel():
			ctx.handleStabilityTimeout()

		case <-ctx.statusUpdateTicker.C:
			ctx.handlePeriodicStatusUpdate()

		case <-ctx.rebootTicker.C:
			ctx.handleRebootCountdown()
		}
	}
}

func (ctx *evalMgrContext) handlePeriodicStatusUpdate() {
	log.Functionf("handlePeriodicStatusUpdate")

	// Update and publish current status with timing info
	ctx.updateTimingFields()
	ctx.publishEvalStatus()
}

func (ctx *evalMgrContext) handleRebootCountdown() {
	// Update reboot countdown if we're in reboot phase
	if ctx.rebootCountdown > 0 {
		ctx.rebootCountdown--
		if ctx.rebootCountdown <= 0 {
			log.Noticef("Reboot countdown expired, executing reboot")
			if err := ctx.executeReboot(); err != nil {
				log.Errorf("Failed to execute reboot: %v", err)
				// Reset countdown for retry in case of failure
				ctx.rebootCountdown = 10
			}
		} else {
			// Update status immediately during countdown to show progress
			ctx.updateTimingFields()
			ctx.publishEvalStatus()
		}
	}
}

func (ctx *evalMgrContext) updateTimingFields() {
	// Update timing fields based on current state
	if ctx.evalStatus.Phase == types.EvalPhaseTesting && !ctx.evalStatus.TestStartTime.IsZero() {
		// Keep existing timing - already set when evaluation started
	} else if ctx.evalStatus.Phase == types.EvalPhaseTesting && ctx.evalStatus.TestStartTime.IsZero() {
		// Start timing if we just entered evaluation phase
		ctx.evalStatus.TestStartTime = time.Now()
		ctx.evalStatus.TestDuration = DefaultStabilityPeriod
	}

	// Update reboot countdown in status
	ctx.evalStatus.RebootCountdown = ctx.rebootCountdown
	ctx.evalStatus.LastUpdated = time.Now()
}

// Note: GlobalConfig handlers removed - evalmgr operates independently
// without requiring controller connectivity or onboarding completion

// publishPreliminaryStatus publishes initial status immediately to prevent client race
func (ctx *evalMgrContext) publishPreliminaryStatus() {
	// Quick platform detection without full initialization
	isEvalPlatform := utils.IsEvaluationPlatform()
	log.Noticef("publishPreliminaryStatus: platform detection result=%t", isEvalPlatform)
	currentSlot := types.SlotName(zboot.GetCurrentPartition())
	if currentSlot == "" {
		currentSlot = types.SlotIMGA // Default fallback
	}

	// Create minimal preliminary status
	prelim := types.EvalStatus{
		IsEvaluationPlatform: isEvalPlatform,
		CurrentSlot:          currentSlot,
		Phase:                types.EvalPhaseInit,
		AllowOnboard:         !isEvalPlatform, // Non-eval platforms can onboard immediately
		Note:                 "Preliminary status - full initialization pending",
		LastUpdated:          time.Now(),
	}

	if err := ctx.pubEvalStatus.Publish(prelim.Key(), prelim); err != nil {
		log.Errorf("Failed to publish preliminary EvalStatus: %v", err)
	} else {
		log.Noticef("Published preliminary EvalStatus: allowOnboard=%t, platform=%t, slot=%s, phase=%s",
			prelim.AllowOnboard, prelim.IsEvaluationPlatform, prelim.CurrentSlot, prelim.Phase)
	}
}

// getStabilityTimerChannel returns the stability timer channel or nil if no timer
func (ctx *evalMgrContext) getStabilityTimerChannel() <-chan time.Time {
	if ctx.stabilityTimer == nil {
		return nil
	}
	return ctx.stabilityTimer.C
}
