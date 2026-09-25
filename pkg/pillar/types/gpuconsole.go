// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

// GPUConsoleConfig is domainmgr asking the console to release the GPU, or
// telling it the GPU is free again. Published by domainmgr, subscribed by the
// monitor agent, which forwards it to whichever console is running.
type GPUConsoleConfig struct {
	// Domain that wants the GPU. Empty when handing it back.
	Domain string
	// Release is true to take the GPU, false to return it.
	Release bool
}

// Key implements the pubsub keyed-object contract. There is one GPU to
// arbitrate, so there is one object.
func (c GPUConsoleConfig) Key() string { return "global" }

// GPUConsoleStatus is the monitor agent's answer. Published by the monitor
// agent, subscribed by domainmgr, which waits on it before binding vfio-pci.
type GPUConsoleStatus struct {
	Domain string
	// Released is true once the console is off the GPU.
	Released bool
	// Error is non-empty when the console could not comply.
	Error string
}

// Key implements the pubsub keyed-object contract.
func (s GPUConsoleStatus) Key() string { return "global" }
