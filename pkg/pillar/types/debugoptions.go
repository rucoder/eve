// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"maps"
	"slices"
	"unicode"
)

// Where a debug option takes effect.
const (
	// DebugScopeConsole options are applied by the local console itself, as
	// soon as it hears of a change.
	DebugScopeConsole = "console"
	// DebugScopeVM options are applied by domainmgr when an application
	// starts, so a change reaches a running application on its next start.
	DebugScopeVM = "vm"
)

// What values a debug option takes.
const (
	DebugKindBool   = "bool" // "true" or "false"
	DebugKindString = "string"
	DebugKindEnum   = "enum" // one of DebugOptionSpec.Choices
)

// Debug option keys.
const (
	DebugVMIntelNoCCS    = "vm.intel_noccs"
	DebugVMMesaDebug     = "vm.mesa_debug"
	DebugVMVrendDebug    = "vm.vrend_debug"
	DebugVMQemuTrace     = "vm.qemu_trace"
	DebugConsoleProbe    = "console.probe"
	DebugConsoleLogLevel = "console.log_level"
	DebugConsoleZbusLog  = "console.zbus_log"
)

// DebugOptionSpec is one entry of DebugOptionCatalogue.
type DebugOptionSpec struct {
	Key         string
	Label       string
	Description string
	Scope       string
	Kind        string
	Choices     []string
	Default     string
}

// DebugOptionCatalogue is every debug option the local console can change,
// in the order the console lists them. The console draws whatever it is sent
// (monitorapi.DebugOptions), so an option needs an entry here plus the code
// that applies it: KvmContext.Setup for scope vm, the console for scope
// console.
var DebugOptionCatalogue = []DebugOptionSpec{
	{
		Key:   DebugVMIntelNoCCS,
		Label: "Intel: no render compression",
		// On by default: iris in Mesa 26.2 exports a render-compressed
		// scanout as its bare main surface, which the console imports as
		// all-black.
		Description: "Render virtual GPUs without Intel render compression " +
			"(INTEL_DEBUG=noccs). Works around black scanouts with Mesa 26.2.",
		Scope:   DebugScopeVM,
		Kind:    DebugKindBool,
		Default: "true",
	},
	{
		Key:   DebugVMMesaDebug,
		Label: "Mesa debug output",
		Description: "Run virtual GPU renderers with MESA_DEBUG=1, which " +
			"reports GL errors on QEMU's stderr.",
		Scope:   DebugScopeVM,
		Kind:    DebugKindBool,
		Default: "false",
	},
	{
		Key:   DebugVMVrendDebug,
		Label: "virglrenderer debug flags",
		Description: "VREND_DEBUG for virtual GPU renderers, e.g. \"all\" or " +
			"\"err,shader\". Empty leaves it unset.",
		Scope:   DebugScopeVM,
		Kind:    DebugKindString,
		Default: "",
	},
	{
		Key:   DebugVMQemuTrace,
		Label: "QEMU trace events",
		Description: "Comma-separated QEMU trace events, globs or @presets " +
			"(@iommu, @barmap, @vfio), added to debug.qemu.trace.events.",
		Scope:   DebugScopeVM,
		Kind:    DebugKindString,
		Default: "",
	},
	{
		Key:   DebugConsoleProbe,
		Label: "Readback probe",
		Description: "Every 600 console frames, read the shown guest image " +
			"back off the GPU and count its non-black pixels: tells a guest " +
			"that draws nothing from pixels the console loses. Stalls the " +
			"GPU pipeline each time.",
		Scope:   DebugScopeConsole,
		Kind:    DebugKindBool,
		Default: "false",
	},
	{
		Key:   DebugConsoleLogLevel,
		Label: "Console log level",
		Description: "The console's own log level. Raises, never lowers, " +
			"debug.tui.loglevel.",
		Scope:   DebugScopeConsole,
		Kind:    DebugKindEnum,
		Choices: []string{"info", "debug", "trace"},
		Default: "info",
	},
	{
		Key:   DebugConsoleZbusLog,
		Label: "D-Bus (zbus) logging",
		Description: "Log the console's D-Bus traffic with QEMU (zbus) at " +
			"the console log level. Off, only zbus warnings are logged: at " +
			"info it logs every call.",
		Scope:   DebugScopeConsole,
		Kind:    DebugKindBool,
		Default: "false",
	},
}

// maxDebugOptionLen bounds a string option. Values end up in a QEMU
// environment and its trace-events file.
const maxDebugOptionLen = 256

// LookupDebugOption returns the catalogue entry for key.
func LookupDebugOption(key string) (DebugOptionSpec, bool) {
	i := slices.IndexFunc(DebugOptionCatalogue, func(s DebugOptionSpec) bool { return s.Key == key })
	if i < 0 {
		return DebugOptionSpec{}, false
	}
	return DebugOptionCatalogue[i], true
}

// Validate checks value against the option's kind.
func (s DebugOptionSpec) Validate(value string) error {
	switch s.Kind {
	case DebugKindBool:
		if value != "true" && value != "false" {
			return fmt.Errorf("%s: %q is not true or false", s.Key, value)
		}
	case DebugKindEnum:
		if !slices.Contains(s.Choices, value) {
			return fmt.Errorf("%s: %q is not one of %v", s.Key, value, s.Choices)
		}
	case DebugKindString:
		if len(value) > maxDebugOptionLen {
			return fmt.Errorf("%s: longer than %d bytes", s.Key, maxDebugOptionLen)
		}
		if i := slices.IndexFunc([]rune(value), unicode.IsControl); i >= 0 {
			return fmt.Errorf("%s: control character at %d", s.Key, i)
		}
	default:
		return fmt.Errorf("%s: unknown kind %q", s.Key, s.Kind)
	}
	return nil
}

// DebugOptionValues is the debug options set from the local console.
// Published by the monitor agent, persistently, and subscribed by domainmgr.
type DebugOptionValues struct {
	// Values holds only the options set to something other than their
	// default, keyed by DebugOptionSpec.Key, so a default changed in a later
	// release reaches every device whose operator never touched it.
	Values map[string]string
}

// Key implements the pubsub keyed-object contract.
func (v DebugOptionValues) Key() string { return "global" }

// Get returns the option's value: the one set, else its default. Empty for
// a key that is not in the catalogue.
func (v DebugOptionValues) Get(key string) string {
	spec, ok := LookupDebugOption(key)
	if !ok {
		return ""
	}
	if value, set := v.Values[key]; set && spec.Validate(value) == nil {
		return value
	}
	return spec.Default
}

// Bool reports whether a bool option is on.
func (v DebugOptionValues) Bool(key string) bool {
	return v.Get(key) == "true"
}

// With returns a copy with key set to value, or an error if the catalogue
// does not allow it. Setting an option back to its default removes it.
func (v DebugOptionValues) With(key, value string) (DebugOptionValues, error) {
	spec, ok := LookupDebugOption(key)
	if !ok {
		return v, fmt.Errorf("unknown debug option %q", key)
	}
	if err := spec.Validate(value); err != nil {
		return v, err
	}
	values := maps.Clone(v.Values)
	if values == nil {
		values = make(map[string]string)
	}
	if value == spec.Default {
		delete(values, key)
	} else {
		values[key] = value
	}
	return DebugOptionValues{Values: values}, nil
}
