// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/client-go/util/jsonpath"
)

// defaultWaitTimeout is used when callers pass a zero timeout. Five
// minutes matches the shell path's default and is long enough for a
// modestly-loaded controller to converge without wedging the boot.
const defaultWaitTimeout = 5 * time.Minute

// ErrWaitDeleted is returned when the object being watched is deleted
// while a Wait* call is in progress. Callers can use errors.Is to
// distinguish this from a plain timeout.
var ErrWaitDeleted = errors.New("kubectlx wait: object was deleted")

// waitOn is the shared driver for the typed Wait* helpers. It builds a
// name-filtered ListWatch on the given resource under kc's clientset,
// starts a watch synced against the current API state, and returns
// once predicate reports done or ctx / timeout expire.
//
// exampleType is the concrete Go type the ListWatch produces (e.g.
// &appsv1.Deployment{}) — watchtools.UntilWithSync uses it to type-
// assert list results back into events during the initial sync.
func waitOn(
	ctx context.Context,
	kc *kubeclient.Client,
	resource string, // "deployments", "daemonsets", "jobs", "customresourcedefinitions"
	group string, // "apps", "batch", "", "apiextensions.k8s.io"
	version string, // "v1"
	namespace, name string,
	timeout time.Duration,
	exampleType runtime.Object,
	predicate func(runtime.Object) (bool, error),
) error {
	if timeout <= 0 {
		timeout = defaultWaitTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Every Wait* call currently supported is a name-lookup — the
	// field selector keeps List/Watch traffic minimal.
	sel := fields.OneTermEqualSelector("metadata.name", name).String()

	lw := &cache.ListWatch{
		ListFunc: func(o metav1.ListOptions) (runtime.Object, error) {
			o.FieldSelector = sel
			return listResource(waitCtx, kc, group, version, resource, namespace, o)
		},
		WatchFunc: func(o metav1.ListOptions) (watch.Interface, error) {
			o.FieldSelector = sel
			return watchResource(waitCtx, kc, group, version, resource, namespace, o)
		},
	}

	_, err := watchtools.UntilWithSync(waitCtx, lw, exampleType, nil,
		func(ev watch.Event) (bool, error) {
			switch ev.Type {
			case watch.Added, watch.Modified:
				return predicate(ev.Object)
			case watch.Deleted:
				return false, ErrWaitDeleted
			case watch.Error:
				return false, apierrors.FromObject(ev.Object)
			}
			return false, nil
		})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("kubectlx wait: %s/%s %s.%s: timeout after %s: %w",
				namespace, name, resource, group, timeout, err)
		}
		return fmt.Errorf("kubectlx wait: %s/%s %s.%s: %w",
			namespace, name, resource, group, err)
	}
	return nil
}

// listResource is the dispatch from (group, version, resource) → the
// right typed clientset method. Only the resources kube-init actually
// waits on are wired up.
func listResource(
	ctx context.Context, kc *kubeclient.Client,
	group, version, resource, namespace string, o metav1.ListOptions,
) (runtime.Object, error) {
	switch {
	case group == "apps" && version == "v1" && resource == "deployments":
		return kc.Clientset.AppsV1().Deployments(namespace).List(ctx, o)
	case group == "apps" && version == "v1" && resource == "daemonsets":
		return kc.Clientset.AppsV1().DaemonSets(namespace).List(ctx, o)
	case group == "batch" && version == "v1" && resource == "jobs":
		return kc.Clientset.BatchV1().Jobs(namespace).List(ctx, o)
	case group == "apiextensions.k8s.io" && version == "v1" && resource == "customresourcedefinitions":
		return kc.APIExtClientset.ApiextensionsV1().CustomResourceDefinitions().List(ctx, o)
	}
	return nil, fmt.Errorf("waitOn: unsupported resource %s.%s/%s", resource, group, version)
}

// watchResource mirrors listResource for the Watch side.
func watchResource(
	ctx context.Context, kc *kubeclient.Client,
	group, version, resource, namespace string, o metav1.ListOptions,
) (watch.Interface, error) {
	switch {
	case group == "apps" && version == "v1" && resource == "deployments":
		return kc.Clientset.AppsV1().Deployments(namespace).Watch(ctx, o)
	case group == "apps" && version == "v1" && resource == "daemonsets":
		return kc.Clientset.AppsV1().DaemonSets(namespace).Watch(ctx, o)
	case group == "batch" && version == "v1" && resource == "jobs":
		return kc.Clientset.BatchV1().Jobs(namespace).Watch(ctx, o)
	case group == "apiextensions.k8s.io" && version == "v1" && resource == "customresourcedefinitions":
		return kc.APIExtClientset.ApiextensionsV1().CustomResourceDefinitions().Watch(ctx, o)
	}
	return nil, fmt.Errorf("waitOn: unsupported resource %s.%s/%s", resource, group, version)
}

// WaitCRDEstablished blocks until the named CRD reports Established=True
// or ctx / timeout expires. This is the intended gate between applying
// a CRD and applying a CR of that kind — the discovery-cache race the
// shell path used to hit is closed by pairing this call with the
// RESTMapper reset that applyOne already performs.
func WaitCRDEstablished(
	ctx context.Context, kc *kubeclient.Client, name string, timeout time.Duration,
) error {
	log.Printf("kubectlx: waiting for CRD %s to be Established (timeout=%s)", name, timeoutStr(timeout))
	return waitOn(ctx, kc,
		"customresourcedefinitions", "apiextensions.k8s.io", "v1",
		"", name, timeout, &apiextv1.CustomResourceDefinition{},
		func(o runtime.Object) (bool, error) {
			crd, ok := o.(*apiextv1.CustomResourceDefinition)
			if !ok {
				return false, nil
			}
			for _, c := range crd.Status.Conditions {
				if c.Type == apiextv1.Established &&
					c.Status == apiextv1.ConditionTrue {
					return true, nil
				}
				if c.Type == apiextv1.NamesAccepted &&
					c.Status == apiextv1.ConditionFalse {
					return false, fmt.Errorf("CRD %s NamesAccepted=False: %s",
						name, c.Message)
				}
			}
			return false, nil
		})
}

// WaitDeploymentReady blocks until the named Deployment has fully
// rolled out: observedGeneration has caught up to metadata.generation
// and every desired replica is available.
//
// Equivalent to `kubectl rollout status deployment/<name>` but reads
// the watch stream directly rather than polling.
func WaitDeploymentReady(
	ctx context.Context, kc *kubeclient.Client, namespace, name string, timeout time.Duration,
) error {
	log.Printf("kubectlx: waiting for deployment %s/%s (timeout=%s)",
		namespace, name, timeoutStr(timeout))
	return waitOn(ctx, kc,
		"deployments", "apps", "v1",
		namespace, name, timeout, &appsv1.Deployment{},
		func(o runtime.Object) (bool, error) {
			d, ok := o.(*appsv1.Deployment)
			if !ok {
				return false, nil
			}
			return isDeploymentReady(d), nil
		})
}

// isDeploymentReady mirrors `kubectl rollout status`'s success clause:
// observed generation matches, no old replicas linger, and every
// desired replica is available.
func isDeploymentReady(d *appsv1.Deployment) bool {
	if d.Generation > d.Status.ObservedGeneration {
		return false
	}
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	if d.Status.UpdatedReplicas < desired {
		return false
	}
	if d.Status.Replicas > d.Status.UpdatedReplicas {
		// Old ReplicaSet's pods still terminating.
		return false
	}
	if d.Status.AvailableReplicas < desired {
		return false
	}
	return true
}

// WaitDaemonSetReady blocks until every desired pod of the DaemonSet is
// ready. Equivalent to `kubectl rollout status daemonset/<name>`.
func WaitDaemonSetReady(
	ctx context.Context, kc *kubeclient.Client, namespace, name string, timeout time.Duration,
) error {
	log.Printf("kubectlx: waiting for daemonset %s/%s (timeout=%s)",
		namespace, name, timeoutStr(timeout))
	return waitOn(ctx, kc,
		"daemonsets", "apps", "v1",
		namespace, name, timeout, &appsv1.DaemonSet{},
		func(o runtime.Object) (bool, error) {
			ds, ok := o.(*appsv1.DaemonSet)
			if !ok {
				return false, nil
			}
			if ds.Generation > ds.Status.ObservedGeneration {
				return false, nil
			}
			if ds.Status.NumberReady < ds.Status.DesiredNumberScheduled {
				return false, nil
			}
			if ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled {
				return false, nil
			}
			return true, nil
		})
}

// WaitJobComplete blocks until the Job reaches Complete=True. Returns
// an error if the Job reports Failed=True instead — callers should not
// retry a Failed Job through the same wait call.
func WaitJobComplete(
	ctx context.Context, kc *kubeclient.Client, namespace, name string, timeout time.Duration,
) error {
	log.Printf("kubectlx: waiting for job %s/%s (timeout=%s)",
		namespace, name, timeoutStr(timeout))
	return waitOn(ctx, kc,
		"jobs", "batch", "v1",
		namespace, name, timeout, &batchv1.Job{},
		func(o runtime.Object) (bool, error) {
			j, ok := o.(*batchv1.Job)
			if !ok {
				return false, nil
			}
			for _, c := range j.Status.Conditions {
				if c.Status != corev1.ConditionTrue {
					continue
				}
				if c.Type == batchv1.JobComplete {
					return true, nil
				}
				if c.Type == batchv1.JobFailed {
					return false, fmt.Errorf("job %s/%s failed: %s",
						namespace, name, c.Message)
				}
			}
			return false, nil
		})
}

// WaitForCondition is the generic fallback for kinds without a
// first-class helper (KubeVirt CR .status.phase, CDI CR .status.phase,
// etc.). It watches the named object via the dynamic client, evaluates
// the JSONPath expression on every event, and returns once the
// evaluated string equals `want`.
//
// Example: WaitForCondition(ctx, kc,
//
//	schema.GroupVersionKind{Group: "kubevirt.io", Version: "v1", Kind: "KubeVirt"},
//	"kubevirt", "kubevirt", "{.status.phase}", "Deployed", 5*time.Minute)
func WaitForCondition(
	ctx context.Context, kc *kubeclient.Client,
	gvk schema.GroupVersionKind, namespace, name, jsonPath, want string,
	timeout time.Duration,
) error {
	if timeout <= 0 {
		timeout = defaultWaitTimeout
	}
	log.Printf("kubectlx: waiting for %s %s/%s %s=%s (timeout=%s)",
		gvk.Kind, namespace, name, jsonPath, want, timeoutStr(timeout))

	jp := jsonpath.New("wait").AllowMissingKeys(true)
	if err := jp.Parse(jsonPath); err != nil {
		return fmt.Errorf("kubectlx wait: parse JSONPath %q: %w", jsonPath, err)
	}

	var mapping *meta.RESTMapping
	if err := withMapperReset(kc, func() error {
		m, err := kc.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return err
		}
		mapping = m
		return nil
	}); err != nil {
		return fmt.Errorf("kubectlx wait: rest mapping for %s: %w", gvk, err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sel := fields.OneTermEqualSelector("metadata.name", name).String()
	dyn := kc.Dynamic.Resource(mapping.Resource)
	var scoped interface {
		List(ctx context.Context, opts metav1.ListOptions) (*unstructured.UnstructuredList, error)
		Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	}
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		scoped = dyn.Namespace(namespace)
	} else {
		scoped = dyn
	}

	lw := &cache.ListWatch{
		ListFunc: func(o metav1.ListOptions) (runtime.Object, error) {
			o.FieldSelector = sel
			return scoped.List(waitCtx, o)
		},
		WatchFunc: func(o metav1.ListOptions) (watch.Interface, error) {
			o.FieldSelector = sel
			return scoped.Watch(waitCtx, o)
		},
	}

	_, err := watchtools.UntilWithSync(waitCtx, lw, &unstructured.Unstructured{}, nil,
		func(ev watch.Event) (bool, error) {
			switch ev.Type {
			case watch.Added, watch.Modified:
				u, ok := ev.Object.(*unstructured.Unstructured)
				if !ok {
					return false, nil
				}
				got, err := evalJSONPath(jp, u.Object)
				if err != nil {
					return false, nil
				}
				return got == want, nil
			case watch.Deleted:
				return false, ErrWaitDeleted
			case watch.Error:
				return false, apierrors.FromObject(ev.Object)
			}
			return false, nil
		})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("kubectlx wait: %s %s/%s %s=%s: timeout after %s: %w",
				gvk.Kind, namespace, name, jsonPath, want, timeout, err)
		}
		return fmt.Errorf("kubectlx wait: %s %s/%s %s=%s: %w",
			gvk.Kind, namespace, name, jsonPath, want, err)
	}
	return nil
}

// evalJSONPath evaluates a parsed JSONPath against an
// unstructured.Object and returns the trimmed string result. Missing
// keys yield "" (not an error) so predicates for optional fields can
// simply compare against "".
func evalJSONPath(jp *jsonpath.JSONPath, obj map[string]any) (string, error) {
	var buf strings.Builder
	if err := jp.Execute(&buf, obj); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// timeoutStr renders a duration for log lines. Short and stable —
// unlike the old formatTimeout it doesn't need to satisfy kubectl's
// argv grammar.
func timeoutStr(d time.Duration) string {
	if d <= 0 {
		d = defaultWaitTimeout
	}
	return d.String()
}
