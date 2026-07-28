// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/deploy"
)

// TestReplaceField covers the indent-preserving line rewriter used
// to substitute base64 cert/key data into the admin kubeconfig.
// The non-trivial properties:
//   - Leading whitespace of the matched line is preserved.
//   - Lines that don't start with the prefix are left alone.
//   - Lines whose prefix appears mid-line (not at start of the
//     trimmed text) are NOT matched.
//   - All matching lines are rewritten (multi-line behaviour).
func TestReplaceField(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		prefix  string
		newVal  string
		want    string
	}{
		{
			name:   "preserves indent on matched line",
			in:     "    client-certificate-data: OLD\n",
			prefix: "client-certificate-data:",
			newVal: "NEW",
			want:   "    client-certificate-data: NEW\n",
		},
		{
			name:   "leaves non-matching lines unchanged",
			in:     "apiVersion: v1\n  client-key-data: OLD\nkind: Config\n",
			prefix: "client-key-data:",
			newVal: "NEW",
			want:   "apiVersion: v1\n  client-key-data: NEW\nkind: Config\n",
		},
		{
			name:   "tab-indented lines preserve their tab",
			in:     "\tclient-certificate-data: OLD",
			prefix: "client-certificate-data:",
			newVal: "NEW",
			want:   "\tclient-certificate-data: NEW",
		},
		{
			name:   "prefix mid-line does NOT match",
			in:     "  # client-certificate-data: should not replace\n",
			prefix: "client-certificate-data:",
			newVal: "NEW",
			want:   "  # client-certificate-data: should not replace\n",
		},
		{
			name: "multiple matching lines all replaced",
			in: "  client-certificate-data: A\n" +
				"  some-other: x\n" +
				"  client-certificate-data: B\n",
			prefix: "client-certificate-data:",
			newVal: "NEW",
			want: "  client-certificate-data: NEW\n" +
				"  some-other: x\n" +
				"  client-certificate-data: NEW\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := replaceField(c.in, c.prefix, c.newVal); got != c.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, c.want)
			}
		})
	}
}

// TestBuildFeatureGatesPatch covers the JSON-string construction
// against quoting/comma edge cases. We don't validate the JSON
// against a parser — the assertion is on the literal output shape
// that kubectl --type=merge -p= consumes.
func TestBuildFeatureGatesPatch(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{
			name: "single gate produces no trailing comma",
			in:   []string{"GPU"},
			want: `{"spec":{"configuration":{"developerConfiguration":{"featureGates":["GPU"]}}}}`,
		},
		{
			name: "multiple gates comma-joined",
			in:   []string{"HostDisk", "Snapshot", "GPU"},
			want: `{"spec":{"configuration":{"developerConfiguration":{"featureGates":["HostDisk","Snapshot","GPU"]}}}}`,
		},
		{
			name: "empty list produces empty array (NOT a null)",
			in:   []string{},
			want: `{"spec":{"configuration":{"developerConfiguration":{"featureGates":[]}}}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildFeatureGatesPatch(c.in); got != c.want {
				t.Errorf("\ngot:  %s\nwant: %s", got, c.want)
			}
		})
	}
}

// TestParseAllNodesReady / TestParseLonghornDSReady were removed:
// the parseAllNodesReady / parseLonghornDSReady helpers exercised
// kubectl-stdout parsing that no longer exists — the equivalent
// checks now read typed Node / DaemonSet objects directly via
// client-go. Rewriting them against fake.NewSimpleClientset is
// task #8 follow-up work; the underlying logic is trivial enough
// to leave uncovered here without shipping a regression.

// TestParseFirstIPv4 covers the `ip -o -4 addr show` parser. Non-
// trivial behaviour:
//   - Strips the /<mask> suffix.
//   - Picks the FIRST inet entry only.
//   - Returns "" on output that has no inet entry.
//   - Doesn't confuse "inet6" with "inet" (we scan fields[i] == "inet").
func TestParseFirstIPv4(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "standard ip -o -4 addr line",
			in:   "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0",
			want: "10.0.0.5",
		},
		{
			name: "first of multiple inet entries wins",
			in: "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255\n" +
				"3: eth1    inet 192.168.1.1/24 brd 192.168.1.255",
			want: "10.0.0.5",
		},
		{
			name: "no inet entry returns empty",
			in:   "2: eth0    state UP qlen 1000",
			want: "",
		},
		{
			name: "inet6 alone does NOT match",
			in:   "2: eth0    inet6 fe80::1/64 scope link",
			want: "",
		},
		{
			name: "empty input returns empty",
			in:   "",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseFirstIPv4(c.in); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestBuildDeployGraph covers the deploy.Graph wiring. The two
// non-trivial properties:
//
//  1. `longhorn` must declare PolicyDeps:["manifests"] — Longhorn's
//     PVC controller needs storage-classes.yaml in the auto-deploy
//     dir before its config applies. A regression here is silent in
//     unit-land and only manifests at runtime.
//
//  2. kubevirt/cdi must be appended ONLY when installKubevirt is
//     true, AND each must carry ReadyTimeout matching the CR-
//     converge budget (without it the deploy package's 30-second
//     default cap fires prematurely).
func TestBuildDeployGraph(t *testing.T) {
	addr := NodeAddress{IP: "10.0.0.5", Prefix: "/32"}

	t.Run("longhorn depends on manifests", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, false /*installKubevirt*/)
		longhorn := findComponent(t, g.Components, "longhorn")
		if len(longhorn.PolicyDeps) != 1 || longhorn.PolicyDeps[0] != "manifests" {
			t.Errorf("longhorn.PolicyDeps = %v, want [manifests]", longhorn.PolicyDeps)
		}
		// No other component should depend on anything (single real
		// edge in the whole graph).
		for _, c := range g.Components {
			if c.Name == "longhorn" {
				continue
			}
			if len(c.PolicyDeps) != 0 {
				t.Errorf("component %q has unexpected PolicyDeps %v", c.Name, c.PolicyDeps)
			}
		}
	})

	t.Run("kubevirt/cdi omitted when flag false", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, false)
		for _, c := range g.Components {
			if c.Name == "kubevirt" || c.Name == "cdi" {
				t.Errorf("did not expect component %q when installKubevirt=false", c.Name)
			}
		}
	})

	t.Run("kubevirt/cdi present with BestEffort + timeout when flag true", func(t *testing.T) {
		g := buildDeployGraph("dev", addr, true)
		kv := findComponent(t, g.Components, "kubevirt")
		cdi := findComponent(t, g.Components, "cdi")
		for _, c := range []*deploy.Component{kv, cdi} {
			if !c.BestEffort {
				t.Errorf("component %q: BestEffort = false, want true", c.Name)
			}
			if c.ReadyTimeout <= 0 {
				t.Errorf("component %q: ReadyTimeout = %v, "+
					"want > 0 (otherwise deploy.go falls back to a 30s default)",
					c.Name, c.ReadyTimeout)
			}
		}
	})
}

func findComponent(t *testing.T, cs []deploy.Component, name string) *deploy.Component {
	t.Helper()
	for i := range cs {
		if cs[i].Name == name {
			return &cs[i]
		}
	}
	t.Fatalf("component %q not in graph", name)
	return nil
}

// TestKubeVirtLabelsToRemove verifies the helper returns exactly
// the label keys containing "kubevirt.io" from a mixed set — used
// by removeKubeVirtNodeLabels to build a merge patch that nulls
// each key. The previous version appended a kubectl-specific "-"
// deletion suffix; under the client-go migration the label keys
// are used directly as JSON patch fields, so the suffix is gone.
// Map iteration is unordered so we verify via set semantics.
func TestKubeVirtLabelsToRemove(t *testing.T) {
	in := map[string]string{
		"kubernetes.io/hostname":       "n1",
		"node.kubevirt.io/cpu-manager": "true",
		"kubevirt.io/schedulable":      "true",
		"node.alpha.kubernetes.io/ttl": "0",
	}
	got := kubeVirtLabelsToRemove(in)

	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		gotSet[k] = true
	}
	if len(got) != 2 ||
		!gotSet["node.kubevirt.io/cpu-manager"] ||
		!gotSet["kubevirt.io/schedulable"] {
		t.Errorf("got %v, want exactly the two kubevirt.io label keys", got)
	}
}
