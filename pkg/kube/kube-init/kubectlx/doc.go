// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kubectlx is kube-init's typed convenience layer over
// client-go and containerd's Go client. Every operation the daemon
// used to perform by shelling out to `k3s kubectl …`, `k3s ctr -n k8s.io …`,
// or `k3s crictl …` is now an in-process API call — no argv assembly,
// no stderr parsing, no re-exec of the multi-call binary.
//
// The public surface splits three ways:
//
//   - Apply / ApplyFile / ApplyURL / Get (apply.go) — dynamic-client
//     server-side apply, with multi-document YAML support and a
//     RESTMapper-reset-and-retry that closes the "CR applied before
//     its CRD is Established" race in one place.
//   - Wait* / WaitForCondition (wait.go) — informer-driven readiness
//     waits (Deployment, DaemonSet, Job, CRD) plus a JSONPath-based
//     generic condition wait for CR-defined status fields.
//   - ContainerdClient (containerd.go) — a thin wrapper over
//     containerd.Client bound to the k8s.io namespace. ImportImage,
//     ImageExists, DeleteImage, ListImages cover every previous
//     `ctr images …` and `crictl inspecti` callsite. cri-api is not
//     a dependency — everything kube-init needed from crictl was an
//     image-service operation, which containerd exposes directly.
//
// Callers construct a *kubeclient.Client once at daemon boot (see the
// kubeclient package) and pass it into every kubectlx function that
// needs a k8s API handle. The containerd client is analogous —
// construct once via NewContainerd(state.ContainerdSocket), Close on
// shutdown.
package kubectlx
