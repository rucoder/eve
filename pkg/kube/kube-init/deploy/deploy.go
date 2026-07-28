// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package deploy provides a dependency-graph runner for kube-init's
// system-component installation. Replaces the previous wave-based
// scheduler with an event-driven work queue: a component runs the
// moment its declared deps reach Ready, regardless of what any
// unrelated slow peer is doing. Design lives at
// .claude/design/kube-init-client-go-and-dag.md §4.5.
//
// The runner is intentionally small:
//   - No persistent state.
//   - Retries belong inside Apply (via kubectlx.ApplyFile's client-go
//     retry loop) OR the BestEffort retry policy (see §4.5.4).
//   - Idempotency belongs inside Apply too.
//
// The planner (see plan) validates the graph, parses Manifests, and
// resolves deps by merging four structural rules (design §4.5.1)
// with the hand-written PolicyDeps escape hatch. Every resolved edge
// is logged with its origin rule so a surprising ordering is
// diagnosable without re-parsing manifests.
//
// The scheduler (see runScheduler) is a single work loop bounded by
// MaxParallel — no per-wave synchronisation barrier. Components with
// no remaining deps enter the ready queue; the loop pulls one at a
// time (bounded by the semaphore), spawns a goroutine that runs
// Apply → Ready → mark satisfied, then enqueues any newly-unblocked
// children.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// Graph is an unordered collection of Components plus options that
// control how Run executes them.
type Graph struct {
	// Components are the units of work. Order does not matter;
	// dependencies are expressed via Component.PolicyDeps (and, in a
	// future revision, via structural rules over Manifests).
	Components []Component

	// MaxParallel caps how many components run concurrently. 0
	// (default) means unbounded — every ready component starts
	// immediately. Set to 1 to force serial execution (useful for
	// debugging).
	MaxParallel int

	// RetryCtx is the parent context for BestEffort background
	// retries. Non-nil enables retries per RetryPolicy: a component
	// whose Apply fails or whose Ready times out under
	// BestEffort=true is re-attempted in a goroutine tied to this
	// ctx, so the retry loop survives Graph.Run's return.
	//
	// Callers must pass a ctx whose lifetime is at least as long
	// as the daemon that owns the Graph — passing Run's own ctx
	// (typically a per-invocation workCtx) defeats the purpose
	// because retries die the moment Run returns.
	//
	// Nil (default) reproduces the previous one-shot BestEffort
	// behaviour: log the failure, continue, never retry.
	RetryCtx context.Context

	// RetryPolicy overrides the default backoff schedule for
	// RetryCtx-driven retries. Zero-valued fields fall back to
	// defaultRetryPolicy.
	RetryPolicy RetryPolicy

	// RetryCallback fires per retry attempt with (name, attempt,
	// err). Optional — pubsub-status publishers wire this to
	// surface "X still retrying, attempt N/6" without tailing
	// logs.
	RetryCallback RetryCallback
}

// Run plans the graph, resolves edges, and executes components as
// their dependencies become satisfied. Blocks until every
// non-BestEffort component has reached Ready (or one has failed) or
// until ctx is cancelled.
//
// Behaviour summary:
//   - Components with no deps start immediately.
//   - Each component's Apply runs first; on success its Ready runs.
//   - A component becomes "satisfied" once Apply and Ready both
//     succeed (or are skipped, or BestEffort'd through).
//   - The first non-BestEffort failure cancels a derived context
//     shared by every in-flight component; peers observe ctx.Done
//     and terminate. Run returns the first error (alphabetical);
//     secondary errors are appended.
//   - Caller ctx cancellation aborts all in-flight components and
//     surfaces as ctx.Err().
//
// Validation errors (empty name, duplicate, unknown dep, self-dep,
// cycle) are returned before any component runs.
func (g Graph) Run(ctx context.Context) error {
	edges, order, err := g.plan()
	if err != nil {
		return err
	}

	if len(g.Components) == 0 {
		return nil
	}

	log.Printf("deploy: graph resolved with %d component(s) and %d edge(s)",
		len(g.Components), len(edges))
	for _, e := range edges {
		log.Printf("deploy: edge %s → %s (%s)", e.From, e.To, e.Rule)
	}

	return g.runScheduler(ctx, order, edges)
}

// Edges returns the resolved dependency edges without running the
// graph. Used by the future k3s-sctl graph subcommand (task #9) to
// dump the ordering for on-device debugging. Errors surface exactly
// as in Run's validation pass.
func (g Graph) Edges() ([]Edge, error) {
	edges, _, err := g.plan()
	return edges, err
}

// plan validates the graph, derives structural edges from Manifests
// (currently a no-op — task #12 populates Manifests), merges in
// PolicyDeps, checks for cycles, and returns:
//   - edges: the full list of dependency edges (each tagged with its
//     origin rule) in a deterministic order (sort by From, To).
//   - order: the component names in a topologically stable order —
//     used only by tests / diagnostics that want a fixed traversal.
//
// The scheduler does NOT consume `order` directly; it drives itself
// off remaining-dep counts derived from `edges`.
func (g Graph) plan() (edges []Edge, order []string, err error) {
	if len(g.Components) == 0 {
		return nil, nil, nil
	}

	byName := make(map[string]*Component, len(g.Components))
	for i := range g.Components {
		c := &g.Components[i]
		if c.Name == "" {
			return nil, nil, errors.New("deploy: component has empty Name")
		}
		if _, dup := byName[c.Name]; dup {
			return nil, nil, fmt.Errorf("deploy: duplicate component name %q", c.Name)
		}
		byName[c.Name] = c
	}

	// Structural rules: derive edges from parsed manifests. Currently
	// a stub — Manifests are unpopulated in the shipping graph. When
	// task #12 populates them, this call returns actual edges. See
	// rules.go for the four structural rules.
	structural, err := deriveStructuralEdges(byName)
	if err != nil {
		return nil, nil, fmt.Errorf("deploy: derive structural edges: %w", err)
	}
	edges = append(edges, structural...)

	// PolicyDeps: hand-written escape hatch for runtime-only deps
	// that k8s doesn't express. Validated against byName.
	for _, c := range g.Components {
		for _, d := range c.PolicyDeps {
			if d == c.Name {
				return nil, nil, fmt.Errorf(
					"deploy: component %q depends on itself", c.Name)
			}
			if _, ok := byName[d]; !ok {
				return nil, nil, fmt.Errorf(
					"deploy: component %q PolicyDeps names unknown component %q",
					c.Name, d)
			}
			edges = append(edges, Edge{From: d, To: c.Name, Rule: "policy"})
		}
	}

	// Deterministic edge order for logs / tests.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Rule < edges[j].Rule
	})

	// Cycle detection + topological ordering (Kahn's algorithm).
	// This also validates that edges don't reference unknown names,
	// but structural and policy passes have already validated that.
	inDegree := make(map[string]int, len(g.Components))
	children := make(map[string][]string, len(g.Components))
	for _, c := range g.Components {
		inDegree[c.Name] = 0
	}
	// Deduplicate edges by (From, To) — structural + policy may
	// legitimately name the same edge twice; each rule still logs
	// once, but the counting-arithmetic below needs uniques.
	seen := make(map[string]bool, len(edges))
	for _, e := range edges {
		key := e.From + "→" + e.To
		if seen[key] {
			continue
		}
		seen[key] = true
		inDegree[e.To]++
		children[e.From] = append(children[e.From], e.To)
	}

	var ready []string
	for name, d := range inDegree {
		if d == 0 {
			ready = append(ready, name)
		}
	}
	sort.Strings(ready)

	remaining := len(g.Components)
	for len(ready) > 0 {
		n := ready[0]
		ready = ready[1:]
		order = append(order, n)
		remaining--
		// Enqueue children whose remaining in-degree drops to zero.
		kids := append([]string(nil), children[n]...)
		sort.Strings(kids)
		for _, k := range kids {
			inDegree[k]--
			if inDegree[k] == 0 {
				ready = append(ready, k)
			}
		}
	}
	if remaining > 0 {
		stuck := make([]string, 0, remaining)
		for name, d := range inDegree {
			if d > 0 {
				stuck = append(stuck, name)
			}
		}
		sort.Strings(stuck)
		return nil, nil, fmt.Errorf(
			"deploy: dependency cycle detected; unscheduled components: %s",
			strings.Join(stuck, ", "))
	}
	return edges, order, nil
}

// runScheduler executes the components as their dependencies become
// satisfied. Uses a single work loop; unlike the previous wave-based
// runner, a component starts the moment its individual deps are
// Ready, not when the whole peer-wave clears.
//
// Concurrency is bounded by g.MaxParallel (unbounded when zero).
// The first non-BestEffort failure cancels the graph ctx and drains
// in-flight goroutines before returning.
func (g Graph) runScheduler(ctx context.Context, order []string, edges []Edge) error {
	// Build lookup tables from the plan.
	byName := make(map[string]*Component, len(g.Components))
	for i := range g.Components {
		byName[g.Components[i].Name] = &g.Components[i]
	}
	remainingDeps := make(map[string]int, len(g.Components))
	children := make(map[string][]string, len(g.Components))
	seen := make(map[string]bool, len(edges))
	for _, e := range edges {
		key := e.From + "→" + e.To
		if seen[key] {
			continue
		}
		seen[key] = true
		remainingDeps[e.To]++
		children[e.From] = append(children[e.From], e.To)
	}

	// Derived ctx we can cancel on first non-BestEffort failure to
	// propagate stop to every in-flight goroutine.
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	// Optional in-flight semaphore.
	var sem chan struct{}
	if g.MaxParallel > 0 {
		sem = make(chan struct{}, g.MaxParallel)
	}

	// Result channel for completed components. Buffered so a
	// completing goroutine never blocks on the coordinator.
	results := make(chan result, len(g.Components))

	// launched / completed counters are single-threaded (only the
	// coordinator loop below touches them). The runner is done when
	// completed == launched — every scheduled goroutine has emitted
	// its result. Components whose deps failed simply never get
	// launched, so they're excluded from the count. This avoids the
	// WaitGroup-reuse race that a "wait for all + close(results)"
	// helper goroutine would introduce (Add(1) from the coordinator
	// after Wait() has already returned is a Go runtime panic).
	launched := 0
	completed := 0

	// launch spawns a component's Apply+Ready in a bounded
	// goroutine. Increments launched (coordinator-only, no race).
	launch := func(name string) {
		c := byName[name]
		launched++
		go func() {
			if sem != nil {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-runCtx.Done():
					results <- result{name: name, err: runCtx.Err(), step: "queue"}
					return
				}
			}
			runOne(runCtx, c, results, g.RetryCtx, g.RetryPolicy, g.RetryCallback)
		}()
	}

	// Kick off every root component (zero remaining deps).
	roots := make([]string, 0)
	for _, name := range order {
		if remainingDeps[name] == 0 {
			roots = append(roots, name)
		}
	}
	for _, name := range roots {
		launch(name)
	}

	// Coordinator loop: consume results, enqueue newly-unblocked
	// children, collect errors. First non-BestEffort failure cancels
	// runCtx (peers observe promptly); errors continue to drain so
	// no goroutine leaks.
	var firstErr error
	var otherErrs []result
	for completed < launched {
		r := <-results
		completed++
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
				cancelRun()
			}
			otherErrs = append(otherErrs, r)
			// Do NOT enqueue children of a failed component — their
			// remainingDeps entry stays > 0, so they never launch and
			// don't contribute to the completed==launched exit
			// condition. Peers already in-flight will observe runCtx.Done
			// and return promptly.
			continue
		}
		// r is a success — enqueue every child whose remaining
		// in-degree drops to zero.
		kids := append([]string(nil), children[r.name]...)
		sort.Strings(kids)
		for _, k := range kids {
			remainingDeps[k]--
			if remainingDeps[k] == 0 {
				launch(k)
			}
		}
	}

	if firstErr == nil {
		return nil
	}
	// Return the alphabetically-first error with the rest appended
	// for context. Preserves the previous runner's error-message
	// convention so callers/tests that grep on message shape keep
	// working.
	sort.Slice(otherErrs, func(i, j int) bool { return otherErrs[i].name < otherErrs[j].name })
	head := otherErrs[0]
	if len(otherErrs) == 1 {
		return fmt.Errorf("component %q %s: %w", head.name, head.step, head.err)
	}
	rest := make([]string, 0, len(otherErrs)-1)
	for _, e := range otherErrs[1:] {
		rest = append(rest, fmt.Sprintf("%q %s: %v", e.name, e.step, e.err))
	}
	return fmt.Errorf("component %q %s: %w (also: %s)",
		head.name, head.step, head.err, strings.Join(rest, "; "))
}

// result is what runOne emits per component. name identifies the
// component; step is "apply", "ready", "queue", or "" on success;
// err is nil on success.
type result struct {
	name string
	step string
	err  error
}

// runOne executes Apply then (if non-nil) Ready for a single
// component. BestEffort components never emit a non-nil err: their
// failures are logged with a "BEST-EFFORT" prefix, downstream deps
// are unblocked immediately, and — if retryCtx is non-nil — a
// background goroutine is spawned to keep re-attempting Apply/Ready
// per retryPolicy (design §4.5.4). The background loop lives until
// success, retryCtx cancel, or MaxAttempts.
func runOne(
	ctx context.Context, c *Component, results chan<- result,
	retryCtx context.Context, retryPolicy RetryPolicy, retryCallback RetryCallback,
) {
	start := time.Now()
	if c.Apply != nil {
		log.Printf("deploy: %s: apply starting", c.Name)
		if err := c.Apply(ctx); err != nil {
			if c.BestEffort {
				log.Printf("deploy: %s: BEST-EFFORT apply FAILED after %s (treated as success, downstream NOT blocked): %v",
					c.Name, time.Since(start).Round(time.Millisecond), err)
				spawnBestEffortRetry(retryCtx, c, retryPolicy, retryCallback, err, "apply")
				results <- result{name: c.Name}
				return
			}
			log.Printf("deploy: %s: apply FAILED after %s: %v",
				c.Name, time.Since(start).Round(time.Millisecond), err)
			results <- result{name: c.Name, step: "apply", err: err}
			return
		}
		log.Printf("deploy: %s: apply complete in %s",
			c.Name, time.Since(start).Round(time.Millisecond))
	}

	if c.Ready == nil {
		results <- result{name: c.Name}
		return
	}

	readyCtx := ctx
	var readyCancel context.CancelFunc
	var readyTimeout time.Duration
	if c.BestEffort {
		readyTimeout = c.ReadyTimeout
		if readyTimeout <= 0 {
			readyTimeout = defaultReadyTimeout
		}
		readyCtx, readyCancel = context.WithTimeout(ctx, readyTimeout)
		defer readyCancel()
	} else if c.ReadyTimeout > 0 {
		readyCtx, readyCancel = context.WithTimeout(ctx, c.ReadyTimeout)
		defer readyCancel()
	}

	readyStart := time.Now()
	log.Printf("deploy: %s: ready starting", c.Name)
	if err := c.Ready(readyCtx); err != nil {
		if c.BestEffort {
			elapsed := time.Since(readyStart).Round(time.Millisecond)
			if errors.Is(readyCtx.Err(), context.DeadlineExceeded) {
				log.Printf("deploy: %s: BEST-EFFORT ready TIMED OUT after %s (cap=%s, treated as success, downstream NOT blocked): %v",
					c.Name, elapsed, readyTimeout, err)
			} else {
				log.Printf("deploy: %s: BEST-EFFORT ready FAILED after %s (treated as success, downstream NOT blocked): %v",
					c.Name, elapsed, err)
			}
			spawnBestEffortRetry(retryCtx, c, retryPolicy, retryCallback, err, "ready")
			results <- result{name: c.Name}
			return
		}
		log.Printf("deploy: %s: ready FAILED after %s: %v",
			c.Name, time.Since(readyStart).Round(time.Millisecond), err)
		results <- result{name: c.Name, step: "ready", err: err}
		return
	}
	log.Printf("deploy: %s: ready complete in %s (total %s)",
		c.Name, time.Since(readyStart).Round(time.Millisecond),
		time.Since(start).Round(time.Millisecond))
	results <- result{name: c.Name}
}
