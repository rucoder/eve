// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"time"
)

// StepFunc is the signature of the imperative Apply / Ready helper on
// a Component. Both are cancelled via the caller's context.
type StepFunc func(ctx context.Context) error

// ReadyPredicate blocks until a Component reaches its operational
// Ready condition or the caller's context / ReadyTimeout expires.
type ReadyPredicate = StepFunc

// Manifest is one apply-able input to a Component. Exactly one of
// File / URL / Bytes is set. Used as a source-of-truth for
// structural dep derivation.
type Manifest struct {
	File  string
	URL   string
	Bytes []byte
}

// Component is a single unit of work in the deploy graph.
type Component struct {
	// Name uniquely identifies the component. Used in log lines and
	// PolicyDeps references. Must be non-empty and unique within a
	// Graph.
	Name string

	// Manifests are the raw files/URLs/bytes this component
	// applies. The runner parses them (once, up front) to build the
	// (gvk, ns, name) inventory used for structural dep derivation.
	// Empty slice is allowed — the component then relies entirely
	// on Apply + PolicyDeps for ordering.
	Manifests []Manifest

	// Apply performs the imperative side of the component's install
	// (state markers, filesystem staging, symlinks, etc.). Runs
	// after any Manifests have been applied — for components whose
	// entire install is a YAML apply this can be nil.
	Apply StepFunc

	// Ready blocks until the component has reached its operational
	// Ready condition or ctx / ReadyTimeout expires. Optional —
	// omit for components whose readiness is implied by Apply
	// (RBAC, ConfigMaps, plans consumed by an already-Ready
	// controller).
	Ready ReadyPredicate

	// BestEffort downgrades any error from Apply / Ready to a
	// logged warning. Downstream components that depend on this
	// one are NOT blocked, the graph run is NOT aborted.
	BestEffort bool

	// ReadyTimeout caps how long Ready may run. Non-BestEffort:
	// exceeding fails the graph. BestEffort: exceeding is logged
	// and treated as success.
	//
	// Zero applies defaultReadyTimeout for BestEffort components;
	// non-BestEffort components run under the caller's ctx when
	// ReadyTimeout is zero.
	ReadyTimeout time.Duration

	// PolicyDeps names other components in the same graph that
	// must reach Ready before this component's Apply runs. The
	// escape hatch for the small set of runtime-only edges k8s
	// doesn't express structurally (longhorn→cdi, multus→kubevirt,
	// longhorn→storage-classes). Merged with structural edges
	// derived from Manifests.
	PolicyDeps []string
}

// Edge is one dependency edge in the resolved graph.
type Edge struct {
	// From is the name of the component that must be Ready first.
	From string
	// To is the name of the dependent component whose Apply is
	// gated on From reaching Ready.
	To string
	// Rule names the derivation source: "crd", "namespace",
	// "webhook", "sa", or "policy". Exactly one per edge.
	Rule string
}

// defaultReadyTimeout caps a BestEffort Component's Ready step when
// ReadyTimeout is left at zero. Chosen to be long enough for a
// healthy controller to converge on a modestly-loaded node but short
// enough that a stuck best-effort wait does not visibly delay later
// phases.
const defaultReadyTimeout = 30 * time.Second

// RetryPolicy governs BestEffort background retries. A component
// whose Apply fails or whose Ready times out under BestEffort=true is
// re-attempted in the background per this policy.
//
// Zero values apply defaultRetryPolicy.
type RetryPolicy struct {
	// Initial is the first inter-attempt sleep. Zero = 30s.
	Initial time.Duration

	// Factor is the exponential multiplier applied between
	// attempts. Zero = 2.0.
	Factor float64

	// Cap caps the per-attempt sleep after exponential growth.
	// Zero = 5min.
	Cap time.Duration

	// MaxAttempts is the absolute cap on retry count (including
	// the first re-Apply after the initial failure — the original
	// in-graph attempt is NOT counted). Zero = 6, which yields a
	// ~30-minute total budget under the default schedule.
	MaxAttempts int
}

// withDefaults returns a copy of p with zero fields filled from
// defaultRetryPolicy.
func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.Initial <= 0 {
		p.Initial = defaultRetryPolicy.Initial
	}
	if p.Factor <= 0 {
		p.Factor = defaultRetryPolicy.Factor
	}
	if p.Cap <= 0 {
		p.Cap = defaultRetryPolicy.Cap
	}
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = defaultRetryPolicy.MaxAttempts
	}
	return p
}

// defaultRetryPolicy is what .withDefaults() applies for zero-value
// RetryPolicy. Exposed as a var (not a const) only so tests can
// point-adjust; production code should not mutate it.
var defaultRetryPolicy = RetryPolicy{
	Initial:     30 * time.Second,
	Factor:      2.0,
	Cap:         5 * time.Minute,
	MaxAttempts: 6,
}

// RetryCallback is fired on every BestEffort retry attempt. `attempt`
// is 1-indexed and counts only the retries — the original failing
// invocation inside the graph run does not fire this callback.
// `err` is the error from the just-completed attempt; nil means the
// retry succeeded and the loop will exit.
//
// Consumers typically publish a "component X still retrying, attempt
// N/6" status line to pubsub so on-device operators can see slow
// convergence without tailing kube-init logs.
type RetryCallback func(name string, attempt int, err error)
