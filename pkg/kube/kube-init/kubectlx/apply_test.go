// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"errors"
	"net/http"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// crdTerminatingErr reproduces what the apiserver returns when a CR is
// applied while its CRD is still finalizing. Observed verbatim on a
// single→cluster transition, where multus is uninstalled and immediately
// re-applied.
func crdTerminatingErr() error {
	return apierrors.NewForbidden(
		schema.GroupResource{
			Group:    "k8s.cni.cncf.io",
			Resource: "network-attachment-definitions",
		},
		"network-instance-attachment",
		errors.New("create not allowed while custom resource definition is terminating"),
	)
}

// kindNotServedErr reproduces the 404 the apiserver returns when the
// resource endpoint for a kind is not (yet) served — the other half of
// the same race, seen once the RESTMapper holds a stale mapping.
func kindNotServedErr() error {
	return apierrors.NewGenericServerResponse(
		http.StatusNotFound, "patch", schema.GroupResource{
			Group:    "k8s.cni.cncf.io",
			Resource: "network-attachment-definitions",
		}, "", "", 0, false)
}

func TestIsCRDLifecycleRace(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"crd terminating", crdTerminatingErr(), true},
		{"kind not served", kindNotServedErr(), true},
		// Permanent verdicts of the same HTTP classes must NOT be
		// swept up: over-broad matching would turn a genuine RBAC
		// denial or a missing object into a 10-attempt backoff.
		{"plain forbidden", apierrors.NewForbidden(
			schema.GroupResource{Resource: "pods"}, "p",
			errors.New("user cannot patch resource")), false},
		{"plain notfound", apierrors.NewNotFound(
			schema.GroupResource{Resource: "pods"}, "p"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCRDLifecycleRace(tc.err); got != tc.want {
				t.Errorf("isCRDLifecycleRace(%v) = %v, want %v",
					tc.err, got, tc.want)
			}
		})
	}
}

// TestIsRetryableCRDRace is the regression guard: both shapes reach
// isRetryable through the Forbidden/NotFound early-outs, which used to
// classify them as permanent and abort the whole transition on the
// first attempt.
func TestIsRetryableCRDRace(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"crd terminating retried", crdTerminatingErr(), true},
		{"kind not served retried", kindNotServedErr(), true},
		{"rbac denial still permanent", apierrors.NewForbidden(
			schema.GroupResource{Resource: "pods"}, "p",
			errors.New("user cannot patch resource")), false},
		{"missing object still permanent", apierrors.NewNotFound(
			schema.GroupResource{Resource: "pods"}, "p"), false},
		{"invalid still permanent", apierrors.NewInvalid(
			schema.GroupKind{Kind: "Pod"}, "p", nil), false},
		{"server timeout retried", apierrors.NewServerTimeout(
			schema.GroupResource{Resource: "pods"}, "patch", 1), true},
		{"unavailable retried", apierrors.NewServiceUnavailable("try later"), true},
		{"conflict retried (unknown class)", apierrors.NewConflict(
			schema.GroupResource{Resource: "pods"}, "p",
			errors.New("conflict")), true},
		{"status 404 with metav1 reason", &apierrors.StatusError{
			ErrStatus: metav1.Status{
				Code:    http.StatusNotFound,
				Reason:  metav1.StatusReasonNotFound,
				Message: "the server could not find the requested resource",
			},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryable(tc.err); got != tc.want {
				t.Errorf("isRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
