// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"flag"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
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
	pubEvalStatus   pubsub.Publication
	subGlobalConfig pubsub.Subscription
	globalConfig    *types.ConfigItemValueMap
	GCInitialized   bool

	// CLI flags can be added here if needed

	// Current state
	isEvaluationPlatform bool
	currentSlot          types.SlotName
	evalStatus           types.EvalStatus

	// Scheduler state
	schedulerState     SchedulerState
	stabilityTimer     *time.Timer
	stabilityStartTime time.Time
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
	ctx := evalMgrContext{
		globalConfig: types.DefaultConfigItemValueMap(),
	}
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

	// Subscribe to GlobalConfig
	ctx.subGlobalConfig, err = ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     agentName,
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: ctx.handleGlobalConfigCreate,
		ModifyHandler: ctx.handleGlobalConfigModify,
		DeleteHandler: ctx.handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		return fmt.Errorf("failed to create GlobalConfig subscription: %w", err)
	}
	ctx.subGlobalConfig.Activate()

	return nil
}

func (ctx *evalMgrContext) run(ps *pubsub.PubSub) error {
	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(stillRunningTime)
	defer stillRunning.Stop()

	// Wait for GlobalConfig initialization
	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

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

	// Start main event loop
	log.Noticef("Starting main event loop")

	for {
		select {
		case <-stillRunning.C:
			ps.StillRunning(agentName, warningTime, errorTime)

		case change := <-ctx.subGlobalConfig.MsgChan():
			ctx.subGlobalConfig.ProcessChange(change)

		case <-ctx.getStabilityTimerChannel():
			ctx.handleStabilityTimeout()
		}
	}
}

func (ctx *evalMgrContext) processGlobalConfigChange(change pubsub.Change) {
	log.Functionf("processGlobalConfigChange")
	if change.Operation == pubsub.Sync {
		log.Functionf("GlobalConfig sync")
	}
}

func (ctx *evalMgrContext) handleGlobalConfigCreate(ctxArg interface{}, key string, statusArg interface{}) {
	ctx.handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func (ctx *evalMgrContext) handleGlobalConfigModify(ctxArg interface{}, key string, statusArg interface{}, oldStatusArg interface{}) {
	ctx.handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func (ctx *evalMgrContext) handleGlobalConfigDelete(ctxArg interface{}, key string, statusArg interface{}) {
	log.Functionf("handleGlobalConfigDelete for %s", key)
}

func (ctx *evalMgrContext) handleGlobalConfigImpl(ctxArg interface{}, key string, statusArg interface{}) {
	ctxPtr := ctxArg.(*evalMgrContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	gcp := agentlog.HandleGlobalConfig(log, ctxPtr.subGlobalConfig, agentName,
		ctxPtr.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctxPtr.globalConfig = gcp
		ctxPtr.GCInitialized = true
	}
	ctxPtr.updateEvalStatus()
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

// publishPreliminaryStatus publishes initial status immediately to prevent client race
func (ctx *evalMgrContext) publishPreliminaryStatus() {
	// Quick platform detection without full initialization
	isEvalPlatform := utils.IsEvaluationPlatform()
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
		log.Noticef("Published preliminary EvalStatus: allowOnboard=%t, platform=%t",
			prelim.AllowOnboard, prelim.IsEvaluationPlatform)
	}
}

// getStabilityTimerChannel returns the stability timer channel or nil if no timer
func (ctx *evalMgrContext) getStabilityTimerChannel() <-chan time.Time {
	if ctx.stabilityTimer == nil {
		return nil
	}
	return ctx.stabilityTimer.C
}
