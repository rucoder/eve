// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"fmt"
	"os"

	containerd "github.com/containerd/containerd/v2/client"
	ctrdimages "github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
)

// K8sContainerdNamespace is the containerd namespace kubelet manages
// pods under. Every image the daemon imports must land here — the
// default containerd namespace is invisible to CRI. Exported so
// mgmtproxy/images/monitor code that logs the namespace does not
// have to redeclare the string.
const K8sContainerdNamespace = "k8s.io"

// ContainerdClient wraps a containerd.Client. Every operation on this
// type carries a ctx tagged with the k8s.io namespace via
// namespaces.WithNamespace — matches the pattern the images-branch
// established for zero-copy image registration, which is the load-
// bearing future consumer of this package.
//
// A ContainerdClient holds one containerd connection; construct once
// per subsystem (or per operation for one-shots) and Close on
// completion. There is no process-wide singleton; the informer-cache
// argument that makes kubeclient a singleton does not apply here.
type ContainerdClient struct {
	client *containerd.Client
}

// NewContainerd dials the containerd socket at socketPath and probes
// the API's health. Fails fast if the socket exists but the daemon
// is not serving RPCs — the alternative is a per-operation error
// wall that hides the actual "containerd is dead" root cause.
//
// Callers own the returned client and must Close it.
func NewContainerd(ctx context.Context, socketPath string) (*ContainerdClient, error) {
	c, err := containerd.New(socketPath)
	if err != nil {
		return nil, fmt.Errorf("kubectlx containerd: dial %s: %w", socketPath, err)
	}
	probeCtx := namespaces.WithNamespace(ctx, K8sContainerdNamespace)
	if serving, err := c.IsServing(probeCtx); err != nil || !serving {
		_ = c.Close()
		if err == nil {
			err = fmt.Errorf("not serving")
		}
		return nil, fmt.Errorf("kubectlx containerd: health check on %s: %w",
			socketPath, err)
	}
	return &ContainerdClient{client: c}, nil
}

// Close releases the containerd connection. Safe to call multiple
// times — the underlying gRPC connection Close is idempotent.
func (cc *ContainerdClient) Close() error {
	if cc == nil || cc.client == nil {
		return nil
	}
	return cc.client.Close()
}

// nsCtx tags ctx with the k8s.io containerd namespace. Every public
// method calls this on the caller's ctx so subsystems don't need to
// remember the namespace convention.
func (cc *ContainerdClient) nsCtx(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, K8sContainerdNamespace)
}

// ImportImage imports every image in the tarball at tarballPath into
// the k8s.io namespace and returns the imported references. Replaces
// the previous `k3s ctr -n k8s.io images import <tarball>` shell-out.
//
// The returned refs are what kubelet's pods will see via CRI once the
// import lands.
func (cc *ContainerdClient) ImportImage(ctx context.Context, tarballPath string) ([]string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return nil, fmt.Errorf("kubectlx containerd: open %s: %w", tarballPath, err)
	}
	defer f.Close()
	imgs, err := cc.client.Import(cc.nsCtx(ctx), f)
	if err != nil {
		return nil, fmt.Errorf("kubectlx containerd: import %s: %w", tarballPath, err)
	}
	refs := make([]string, 0, len(imgs))
	for _, img := range imgs {
		refs = append(refs, img.Name)
	}
	return refs, nil
}

// ImageExists returns true if the given image reference is present in
// the k8s.io namespace. Replaces the previous crictl inspecti / ctr
// images ls presence probes. NotFound folds into (false, nil); any
// other error surfaces.
func (cc *ContainerdClient) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, err := cc.client.ImageService().Get(cc.nsCtx(ctx), ref)
	if err == nil {
		return true, nil
	}
	if errdefs.IsNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("kubectlx containerd: get image %s: %w", ref, err)
}

// DeleteImage removes the image with the given reference. NotFound
// folds into nil — the caller's intent (image absent) is already
// satisfied. SynchronousDelete guarantees the underlying content is
// unreferenced before we return, so a subsequent import cannot race
// a lingering reference.
func (cc *ContainerdClient) DeleteImage(ctx context.Context, ref string) error {
	err := cc.client.ImageService().Delete(cc.nsCtx(ctx), ref,
		ctrdimages.SynchronousDelete())
	if err == nil || errdefs.IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("kubectlx containerd: delete image %s: %w", ref, err)
}

// TagImage creates a new image record named dst pointing at the
// same descriptor as src. Replaces `ctr images tag <src> <dst>`.
// If a record named dst already exists it is overwritten; if src
// does not exist the error is surfaced.
func (cc *ContainerdClient) TagImage(ctx context.Context, src, dst string) error {
	ctx = cc.nsCtx(ctx)
	is := cc.client.ImageService()
	srcImg, err := is.Get(ctx, src)
	if err != nil {
		return fmt.Errorf("kubectlx containerd: get %s: %w", src, err)
	}
	srcImg.Name = dst
	// Create; if the tag already exists, update by delete + create.
	if _, err := is.Create(ctx, srcImg); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return fmt.Errorf("kubectlx containerd: create tag %s: %w", dst, err)
		}
		if err := is.Delete(ctx, dst); err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("kubectlx containerd: replace tag %s (delete): %w", dst, err)
		}
		if _, err := is.Create(ctx, srcImg); err != nil {
			return fmt.Errorf("kubectlx containerd: replace tag %s (create): %w", dst, err)
		}
	}
	return nil
}

// ListImages returns every image reference in the k8s.io namespace.
// Replaces the previous `ctr images list -q` shell-out.
func (cc *ContainerdClient) ListImages(ctx context.Context) ([]string, error) {
	imgs, err := cc.client.ImageService().List(cc.nsCtx(ctx))
	if err != nil {
		return nil, fmt.Errorf("kubectlx containerd: list images: %w", err)
	}
	refs := make([]string, 0, len(imgs))
	for _, img := range imgs {
		refs = append(refs, img.Name)
	}
	return refs, nil
}
