// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
)

// debugOptionValues is what the console has set so far. The publication is
// persistent, so after a restart it already holds what was set before.
func (ctx *monitor) debugOptionValues() types.DebugOptionValues {
	item, err := ctx.pubDebugOptionValues.Get(types.DebugOptionValues{}.Key())
	if err != nil {
		return types.DebugOptionValues{}
	}
	return item.(types.DebugOptionValues)
}

// debugOptionsToContract lists the whole catalogue with the current values.
func debugOptionsToContract(values types.DebugOptionValues) monitorapi.DebugOptions {
	options := make([]monitorapi.DebugOption, 0, len(types.DebugOptionCatalogue))
	for _, spec := range types.DebugOptionCatalogue {
		options = append(options, monitorapi.DebugOption{
			Key:         spec.Key,
			Label:       spec.Label,
			Description: spec.Description,
			Scope:       spec.Scope,
			Kind:        spec.Kind,
			Choices:     spec.Choices,
			Value:       values.Get(spec.Key),
		})
	}
	return monitorapi.DebugOptions{Options: options}
}

func (ctx *monitor) sendDebugOptions() {
	ctx.IPCServer.sendIpcMessage(monitorapi.DebugOptionsTag,
		debugOptionsToContract(ctx.debugOptionValues()))
}

// handleSetDebugOption publishes the change and sends the console the result.
// A rejected change is sent back too: the console shows pillar's value, not
// the one it asked for, and has to be told it did not take.
func (ctx *monitor) handleSetDebugOption(req monitorapi.SetDebugOption) error {
	ctx.debugMu.Lock()
	defer ctx.debugMu.Unlock()
	defer ctx.sendDebugOptions()

	values, err := ctx.debugOptionValues().With(req.Key, req.Value)
	if err != nil {
		log.Warnf("handleSetDebugOption: ignoring %s=%q: %v", req.Key, req.Value, err)
		return err
	}
	if err := ctx.pubDebugOptionValues.Publish(values.Key(), values); err != nil {
		log.Errorf("handleSetDebugOption: publish: %v", err)
		return err
	}
	log.Noticef("debug option %s set to %q", req.Key, req.Value)
	return nil
}
