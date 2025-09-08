// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// FaultConfigFile contains fault injection configuration
	FaultConfigFile = "/persist/eval/faults.json"
)

// performFaultInjection checks for and executes configured fault injection
func (ctx *evalMgrContext) performFaultInjection() error {
	// Only perform fault injection on evaluation platforms
	if !ctx.isEvaluationPlatform {
		return nil
	}

	faultConfig, err := ctx.loadFaultConfig()
	if err != nil {
		// If no fault config or error loading, that's fine - just continue normally
		log.Functionf("No fault injection config: %v", err)
		return nil
	}

	if !faultConfig.Enabled {
		log.Functionf("Fault injection disabled in config")
		return nil
	}

	// Look for fault configuration for current slot
	slotFault, exists := faultConfig.Slots[ctx.currentSlot]
	if !exists {
		log.Functionf("No fault injection configured for slot %s", ctx.currentSlot)
		return nil
	}

	log.Noticef("Executing fault injection for slot %s: action=%s",
		ctx.currentSlot, slotFault.Action)

	return ctx.executeFault(slotFault)
}

// loadFaultConfig loads fault injection configuration from disk
func (ctx *evalMgrContext) loadFaultConfig() (*types.FaultInjectConfig, error) {
	data, err := os.ReadFile(FaultConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read fault config: %w", err)
	}

	var config types.FaultInjectConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse fault config: %w", err)
	}

	return &config, nil
}

// executeFault performs the specified fault action
func (ctx *evalMgrContext) executeFault(fault types.FaultConfig) error {
	if fault.Note != "" {
		log.Noticef("Fault injection note: %s", fault.Note)
	}

	switch fault.Action {
	case types.FaultActionNone:
		log.Noticef("Fault action: none - continuing normally")
		return nil

	case types.FaultActionDelay:
		delaySeconds := fault.DelaySeconds
		if delaySeconds <= 0 {
			delaySeconds = 30 // Default delay
		}
		log.Noticef("Fault action: delaying boot for %d seconds", delaySeconds)
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		return nil

	case types.FaultActionPanic:
		log.Errorf("Fault action: triggering kernel panic")
		return ctx.triggerKernelPanic()

	case types.FaultActionReboot:
		log.Errorf("Fault action: forcing immediate reboot")
		return ctx.forceReboot()

	default:
		return fmt.Errorf("unknown fault action: %s", fault.Action)
	}
}

// triggerKernelPanic triggers a kernel panic using sysrq
func (ctx *evalMgrContext) triggerKernelPanic() error {
	// Enable sysrq
	if err := os.WriteFile("/proc/sys/kernel/sysrq", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable sysrq: %w", err)
	}

	// Trigger panic
	if err := os.WriteFile("/proc/sysrq-trigger", []byte("c"), 0644); err != nil {
		return fmt.Errorf("failed to trigger panic: %w", err)
	}

	return nil
}

// forceReboot forces an immediate system reboot
func (ctx *evalMgrContext) forceReboot() error {
	// Use reboot -f for immediate reboot without clean shutdown
	cmd := exec.Command("reboot", "-f")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute reboot: %w", err)
	}
	return nil
}

// createExampleFaultConfig creates an example fault configuration file
func (ctx *evalMgrContext) createExampleFaultConfig() error {
	exampleConfig := types.FaultInjectConfig{
		Enabled: false,
		Slots: map[types.SlotName]types.FaultConfig{
			types.SlotIMGA: {
				Action: types.FaultActionNone,
				Note:   "No fault injection for IMGA",
			},
			types.SlotIMGB: {
				Action:       types.FaultActionDelay,
				DelaySeconds: 60,
				Note:         "Delay IMGB boot by 60 seconds",
			},
			types.SlotIMGC: {
				Action: types.FaultActionReboot,
				Note:   "Force reboot when IMGC boots",
			},
		},
	}

	data, err := json.MarshalIndent(exampleConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal example config: %w", err)
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll("/persist/eval", 0755); err != nil {
		return fmt.Errorf("failed to create eval directory: %w", err)
	}

	exampleFile := FaultConfigFile + ".example"
	if err := os.WriteFile(exampleFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write example config: %w", err)
	}

	log.Noticef("Created example fault config at %s", exampleFile)
	return nil
}
