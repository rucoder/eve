// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"
)

func TestEvalStatus_IsOnboardingAllowed(t *testing.T) {
	tests := []struct {
		name     string
		status   EvalStatus
		expected bool
	}{
		{
			name: "non-evaluation platform always allows",
			status: EvalStatus{
				IsEvaluationPlatform: false,
				AllowOnboard:         false, // Even if explicitly disabled
				Phase:                EvalPhaseInit,
			},
			expected: true,
		},
		{
			name: "evaluation platform init phase with allow=true",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         true,
				Phase:                EvalPhaseInit,
			},
			expected: true,
		},
		{
			name: "evaluation platform init phase with allow=false",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         false,
				Phase:                EvalPhaseInit,
			},
			expected: false,
		},
		{
			name: "evaluation platform testing phase with allow=true",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         true,
				Phase:                EvalPhaseTesting,
			},
			expected: true,
		},
		{
			name: "evaluation platform testing phase with allow=false",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         false,
				Phase:                EvalPhaseTesting,
			},
			expected: false,
		},
		{
			name: "evaluation platform final phase always allows when allow=true",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         true,
				Phase:                EvalPhaseFinal,
			},
			expected: true,
		},
		{
			name: "evaluation platform final phase blocked when allow=false",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         false,
				Phase:                EvalPhaseFinal,
			},
			expected: false,
		},
		{
			name: "evaluation platform unknown phase is conservative",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         true,
				Phase:                EvalPhase("unknown"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.status.IsOnboardingAllowed()
			if result != tt.expected {
				t.Errorf("IsOnboardingAllowed() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestEvalStatus_OnboardingBlockReason(t *testing.T) {
	tests := []struct {
		name     string
		status   EvalStatus
		expected string
	}{
		{
			name: "non-evaluation platform has no block reason",
			status: EvalStatus{
				IsEvaluationPlatform: false,
				AllowOnboard:         false,
				Phase:                EvalPhaseInit,
			},
			expected: "",
		},
		{
			name: "allowed onboarding has no block reason",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         true,
				Phase:                EvalPhaseFinal,
			},
			expected: "",
		},
		{
			name: "init phase with allow=false",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         false,
				Phase:                EvalPhaseInit,
			},
			expected: "evaluation platform initializing",
		},
		{
			name: "testing phase with allow=false",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         false,
				Phase:                EvalPhaseTesting,
			},
			expected: "evaluation platform testing in progress",
		},
		{
			name: "final phase with allow=false",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         false,
				Phase:                EvalPhaseFinal,
			},
			expected: "evaluation complete but onboarding explicitly disabled",
		},
		{
			name: "unknown phase with allow=false",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         false,
				Phase:                EvalPhase("unknown"),
			},
			expected: "evaluation platform not ready",
		},
		{
			name: "testing phase with allow=true but blocked by phase logic",
			status: EvalStatus{
				IsEvaluationPlatform: true,
				AllowOnboard:         true,
				Phase:                EvalPhaseTesting,
			},
			expected: "", // This case is actually allowed, so no reason
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.status.OnboardingBlockReason()
			if result != tt.expected {
				t.Errorf("OnboardingBlockReason() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestEvalStatus_Key(t *testing.T) {
	status := EvalStatus{}
	expected := "global"
	result := status.Key()
	if result != expected {
		t.Errorf("Key() = %q, expected %q", result, expected)
	}
}

func TestEvalStatus_LogKey(t *testing.T) {
	status := EvalStatus{}
	expected := "eval_status-global"
	result := status.LogKey()
	if result != expected {
		t.Errorf("LogKey() = %q, expected %q", result, expected)
	}
}

// TestEvalStatus_ComplexScenarios tests real-world scenarios
func TestEvalStatus_ComplexScenarios(t *testing.T) {
	// Scenario 1: Boot sequence on evaluation platform
	t.Run("boot sequence scenario", func(t *testing.T) {
		// Initial state: platform starting up
		bootStatus := EvalStatus{
			IsEvaluationPlatform: true,
			CurrentSlot:          SlotIMGA,
			Phase:                EvalPhaseInit,
			AllowOnboard:         false,
			Note:                 "Evaluation platform initializing",
			LastUpdated:          time.Now(),
		}

		if bootStatus.IsOnboardingAllowed() {
			t.Error("Should not allow onboarding during initialization")
		}
		if reason := bootStatus.OnboardingBlockReason(); reason == "" {
			t.Error("Should provide reason for blocking onboarding")
		}

		// Testing phase: evaluation in progress
		testingStatus := bootStatus
		testingStatus.Phase = EvalPhaseTesting
		testingStatus.Note = "Testing slot IMGA"

		if testingStatus.IsOnboardingAllowed() {
			t.Error("Should not allow onboarding during testing by default")
		}

		// Manual override during testing
		overrideStatus := testingStatus
		overrideStatus.AllowOnboard = true
		overrideStatus.Note = "Manual override enabled"

		if !overrideStatus.IsOnboardingAllowed() {
			t.Error("Should allow onboarding when manually overridden")
		}

		// Final phase: evaluation complete
		finalStatus := EvalStatus{
			IsEvaluationPlatform: true,
			CurrentSlot:          SlotIMGA,
			Phase:                EvalPhaseFinal,
			AllowOnboard:         true,
			Note:                 "Evaluation complete, slot IMGA selected",
			LastUpdated:          time.Now(),
		}

		if !finalStatus.IsOnboardingAllowed() {
			t.Error("Should allow onboarding when evaluation is complete")
		}
		if reason := finalStatus.OnboardingBlockReason(); reason != "" {
			t.Errorf("Should not block onboarding when complete, got reason: %s", reason)
		}
	})

	// Scenario 2: Normal platform behavior
	t.Run("normal platform scenario", func(t *testing.T) {
		normalStatus := EvalStatus{
			IsEvaluationPlatform: false,
			CurrentSlot:          SlotIMGA,
			Phase:                EvalPhaseInit,
			AllowOnboard:         false, // Even if false
			Note:                 "Normal platform",
			LastUpdated:          time.Now(),
		}

		if !normalStatus.IsOnboardingAllowed() {
			t.Error("Normal platforms should always allow onboarding")
		}
		if reason := normalStatus.OnboardingBlockReason(); reason != "" {
			t.Errorf("Normal platforms should not block onboarding, got reason: %s", reason)
		}
	})
}
