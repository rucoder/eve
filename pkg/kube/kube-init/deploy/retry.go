// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"time"
)

// spawnBestEffortRetry launches a background goroutine that keeps
// retrying a failed BestEffort component's Apply+Ready cycle until
// success, retryCtx cancel, or policy.MaxAttempts. The goroutine
// runs entirely under retryCtx (not the graph's per-invocation
// runCtx), so it survives Graph.Run's return.
//
// This is the design-doc §4.5.4 loop that closes Erik's CDI parking
// bug: the previous one-shot BestEffort would log a failure and
// leave the component permanently un-reconciled; here we keep
// trying with exponential backoff until either the component
// converges or the daemon shuts down.
//
// A nil retryCtx is a no-op — the caller in runOne guards on this
// so components without RetryCtx wired retain the previous
// log-and-forget behaviour.
func spawnBestEffortRetry(
	retryCtx context.Context,
	c *Component,
	policy RetryPolicy,
	callback RetryCallback,
	firstErr error,
	firstStep string,
) {
	if retryCtx == nil {
		return
	}
	policy = policy.withDefaults()
	go retryLoop(retryCtx, c, policy, callback, firstErr, firstStep)
}

// retryLoop is the runnable body of the retry goroutine. Exported
// only in package scope (lower-case) so tests can drive it directly
// with a short-schedule policy.
func retryLoop(
	retryCtx context.Context,
	c *Component,
	policy RetryPolicy,
	callback RetryCallback,
	firstErr error,
	firstStep string,
) {
	log.Printf("deploy: %s: BEST-EFFORT retry scheduled after %s failure: %v",
		c.Name, firstStep, firstErr)

	backoff := policy.Initial
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		// Sleep first (initial delay applies before attempt 1);
		// exponential + jitter capped at policy.Cap. Jitter is
		// [0, backoff/2) — bounds the sleep in [backoff, 1.5*backoff)
		// and prevents thundering herd if multiple components all
		// hit the same slow API window.
		jitter := time.Duration(rng.Int63n(int64(backoff/2 + 1)))
		sleep := backoff + jitter
		select {
		case <-retryCtx.Done():
			log.Printf("deploy: %s: BEST-EFFORT retry abandoned (ctx cancelled during sleep, attempt %d/%d)",
				c.Name, attempt, policy.MaxAttempts)
			return
		case <-time.After(sleep):
		}

		// Bound this attempt's Ready by ReadyTimeout so a wedged
		// Ready doesn't hold the retry loop indefinitely — the
		// next iteration re-arms Apply → Ready per §4.5.4.
		attemptCtx := retryCtx
		var cancel context.CancelFunc
		readyTimeout := c.ReadyTimeout
		if readyTimeout <= 0 {
			readyTimeout = defaultReadyTimeout
		}
		attemptCtx, cancel = context.WithTimeout(retryCtx, readyTimeout+policy.Cap)
		err := runApplyThenReady(attemptCtx, c, readyTimeout)
		cancel()

		if callback != nil {
			callback(c.Name, attempt, err)
		}

		if err == nil {
			log.Printf("deploy: %s: BEST-EFFORT retry SUCCEEDED on attempt %d/%d",
				c.Name, attempt, policy.MaxAttempts)
			return
		}

		log.Printf("deploy: %s: BEST-EFFORT retry attempt %d/%d FAILED: %v",
			c.Name, attempt, policy.MaxAttempts, err)

		// Advance backoff for next iteration.
		backoff = time.Duration(float64(backoff) * policy.Factor)
		if backoff > policy.Cap {
			backoff = policy.Cap
		}

		// Honour cancel between attempts too — the sleep above
		// already checks ctx, but retryCtx may cancel while the
		// attempt itself is running. In that case attemptCtx would
		// have surfaced ctx.Err via `err`, and we'd re-loop, sleep,
		// and observe ctx.Done. Fast-path exit here saves that
		// extra iteration.
		if retryCtx.Err() != nil {
			log.Printf("deploy: %s: BEST-EFFORT retry abandoned (ctx cancelled between attempts, attempt %d/%d)",
				c.Name, attempt, policy.MaxAttempts)
			return
		}
	}
	log.Printf("deploy: %s: BEST-EFFORT retry EXHAUSTED after %d attempts",
		c.Name, policy.MaxAttempts)
}

// runApplyThenReady is the retry-loop's per-attempt worker. Runs
// Apply and (if defined and Apply succeeded) Ready. The Ready call
// is bounded by readyTimeout — the retry loop re-arms Apply on
// Ready timeout per design §4.5.4.
//
// Returns nil on success (both Apply and Ready satisfied) or the
// first non-nil step error.
func runApplyThenReady(ctx context.Context, c *Component, readyTimeout time.Duration) error {
	if c.Apply != nil {
		if err := c.Apply(ctx); err != nil {
			return err
		}
	}
	if c.Ready == nil {
		return nil
	}
	readyCtx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	if err := c.Ready(readyCtx); err != nil {
		// DeadlineExceeded is surfaced explicitly so the caller can
		// distinguish "Ready is still converging" from "Apply produced
		// a permanent error"; today the retry loop treats both the
		// same (schedule another attempt), but a future refinement
		// could shortcut permanent errors.
		if errors.Is(readyCtx.Err(), context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return err
	}
	return nil
}
