// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Readiness-wait cadences. Vars so tests can shrink them.
var (
	kubeconfigPollInterval = 5 * time.Second
	nodeReadyPollInterval  = 5 * time.Second
	podReadyPollInterval   = 10 * time.Second
)

// WaitReady blocks until k3s is fully operational: kubeconfig
// appeared + copied, the local node reports Ready, the node-uuid
// label is applied, and every pod in kube-system is Ready.
//
// The supplied timeout bounds the whole sequence (a fresh
// context.WithTimeout is derived from ctx and consumed inside).
//
// Step 4 (label node) is non-fatal — a label-application failure
// only matters for cross-node addressing in HA clusters and the FSM
// can retry later.
func WaitReady(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := WaitKubeconfig(ctx); err != nil {
		return fmt.Errorf("wait kubeconfig: %w", err)
	}

	// Build a client-go clientset now that the kubeconfig exists.
	// Dial errors against the not-yet-serving API surface as
	// per-Get failures below and drive the poll loops — no shell-out.
	// This client is local to WaitReady; the daemon-scoped
	// kubeclient.Default() is initialised separately by main.
	kc, err := kubeclient.New(state.K3sKubeconfig)
	if err != nil {
		return fmt.Errorf("build kubeclient: %w", err)
	}

	info, ok := edgenodeinfo.Get()
	if !ok {
		return fmt.Errorf("EdgeNodeInfo not yet published; subscription has not delivered")
	}
	if info.DeviceName == "" {
		return fmt.Errorf("EdgeNodeInfo.DeviceName is empty (corrupted payload)")
	}
	uuid := info.DeviceID.String()
	if uuid == "" {
		return fmt.Errorf("EdgeNodeInfo.DeviceID is empty (corrupted payload)")
	}
	nodeName := state.ToK8sName(info.DeviceName)

	if err := waitNodeReady(ctx, kc.Clientset, nodeName); err != nil {
		return fmt.Errorf("wait node ready: %w", err)
	}

	if err := labelNodeUUID(ctx, kc.Clientset, nodeName, uuid); err != nil {
		log.Printf("warning: failed to label node %s with uuid: %v", nodeName, err)
	}

	if err := waitSystemPodsReady(ctx, kc.Clientset); err != nil {
		return fmt.Errorf("wait system pods ready: %w", err)
	}
	log.Printf("k3s is fully ready")
	return nil
}

// WaitKubeconfig polls state.K3sKubeconfig until it appears, then
// copies it to KubeconfigCopy. The poll honours ctx — the caller is
// expected to bound the wait via context.WithTimeout.
func WaitKubeconfig(ctx context.Context) error {
	log.Printf("waiting for kubeconfig at %s", state.K3sKubeconfig)

	ticker := time.NewTicker(kubeconfigPollInterval)
	defer ticker.Stop()
	for {
		present, err := fileExists(state.K3sKubeconfig)
		if err != nil {
			return fmt.Errorf("stat %s: %w", state.K3sKubeconfig, err)
		}
		if present {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s: %w",
				state.K3sKubeconfig, ctx.Err())
		case <-ticker.C:
		}
	}

	if err := copyKubeconfig(); err != nil {
		return fmt.Errorf("copy kubeconfig: %w", err)
	}
	log.Printf("kubeconfig ready and copied to %s", KubeconfigCopy)
	return nil
}

// fileExists is the cousin of os.Stat that distinguishes
// "definitely absent" (false, nil) from "we cannot tell" (false,
// err) — silently treating EACCES/EIO as "absent" hides the
// underlying breakage from the FSM.
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}

// copyKubeconfig atomically copies state.K3sKubeconfig to
// KubeconfigCopy, ensuring the destination directory exists.
func copyKubeconfig() error {
	if err := os.MkdirAll(KubeconfigCopyDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", KubeconfigCopyDir, err)
	}
	data, err := os.ReadFile(state.K3sKubeconfig)
	if err != nil {
		return fmt.Errorf("read %s: %w", state.K3sKubeconfig, err)
	}
	if err := state.AtomicWriteFile(KubeconfigCopy, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", KubeconfigCopy, err)
	}
	return nil
}

// waitNodeReady polls the API server until the named node reports
// Ready=True. API-server dial errors and NotFound (node hasn't
// registered yet) drive the poll — anything else surfaces.
func waitNodeReady(ctx context.Context, cs kubernetes.Interface, nodeName string) error {
	log.Printf("waiting for node %s to be Ready", nodeName)

	ticker := time.NewTicker(nodeReadyPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for node %s to be Ready: %w",
				nodeName, ctx.Err())
		case <-ticker.C:
		}
		n, err := cs.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
		if err != nil {
			// API not up yet, or node not registered — keep polling.
			continue
		}
		if nodeIsReady(n) {
			log.Printf("node %s is Ready", nodeName)
			return nil
		}
	}
}

// nodeIsReady inspects a Node's status conditions and returns true
// when the Ready condition is True.
func nodeIsReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// labelNodeUUID applies the `node-uuid=<uuid>` label to nodeName,
// overwriting any prior value. Uses a JSON merge patch so partial
// label maps on the object are preserved.
func labelNodeUUID(ctx context.Context, cs kubernetes.Interface, nodeName, uuid string) error {
	patch := fmt.Sprintf(`{"metadata":{"labels":{"node-uuid":%q}}}`, uuid)
	_, err := cs.CoreV1().Nodes().Patch(ctx, nodeName,
		types.MergePatchType, []byte(patch), metav1.PatchOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("label node %s: not found (registration race?): %w",
				nodeName, err)
		}
		return fmt.Errorf("label node %s: %w", nodeName, err)
	}
	log.Printf("labelled node %s with node-uuid=%s", nodeName, uuid)
	return nil
}

// waitSystemPodsReady blocks until every pod in kube-system reports
// Ready or has finished (Completed/Succeeded). Progress is logged
// every time the ready/total count changes, including the list of
// pods we are still waiting on.
func waitSystemPodsReady(ctx context.Context, cs kubernetes.Interface) error {
	log.Printf("waiting for all system pods to be Ready")
	ticker := time.NewTicker(podReadyPollInterval)
	defer ticker.Stop()

	var lastReady, lastTotal int
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for system pods: %w", ctx.Err())
		case <-ticker.C:
		}
		ready, total, notReady := countSystemPods(ctx, cs)
		if total == 0 {
			continue
		}
		if ready != lastReady || total != lastTotal {
			if len(notReady) > 0 {
				log.Printf("system pods: [%d/%d] ready, waiting on: %s",
					ready, total, strings.Join(notReady, ", "))
			}
			lastReady, lastTotal = ready, total
		}
		if ready == total {
			log.Printf("all system pods are Ready [%d/%d]", ready, total)
			return nil
		}
	}
}

// countSystemPods lists kube-system pods and classifies each by
// readiness. Transient API errors collapse to (0, 0, nil) — the
// caller keeps polling.
func countSystemPods(ctx context.Context, cs kubernetes.Interface) (int, int, []string) {
	pods, err := cs.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil || pods == nil || len(pods.Items) == 0 {
		return 0, 0, nil
	}
	var ready, total int
	var notReady []string
	for _, p := range pods.Items {
		total++
		if p.Status.Phase == corev1.PodSucceeded {
			ready++
			continue
		}
		if p.Status.Phase != corev1.PodRunning {
			notReady = append(notReady, p.Name+"("+string(p.Status.Phase)+")")
			continue
		}
		if podContainersReady(&p) {
			ready++
		} else {
			notReady = append(notReady, p.Name+"("+string(p.Status.Phase)+")")
		}
	}
	return ready, total, notReady
}

// podContainersReady returns true if every container has Ready=True.
// Matches `kubectl get pods` READY column semantics.
func podContainersReady(p *corev1.Pod) bool {
	if len(p.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, cs := range p.Status.ContainerStatuses {
		if !cs.Ready {
			return false
		}
	}
	return true
}
