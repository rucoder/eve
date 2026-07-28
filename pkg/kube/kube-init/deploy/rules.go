// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

// deriveStructuralEdges builds the set of dependency edges implied
// by the Manifests each Component declares. Four rules apply
// (design doc §4.5.1):
//
//  1. CRD → CR: for each CR of kind K in group G, if some component
//     provides `CustomResourceDefinition/K.G`, add edge
//     `provider → owner(CR)`.
//  2. Namespace → namespaced resource: for each namespaced object in
//     namespace N, if some component provides `Namespace/N`, add
//     edge `provider → owner(resource)`.
//  3. Webhook service → webhooked resource: for each
//     Validating/MutatingWebhookConfiguration W pointing at Service
//     `NS/S`, add edges from the component owning `Service/NS/S` (and
//     its backing Deployment) to every other component whose objects
//     match W's rules.
//  4. ServiceAccount → Pod-spec: for each Pod-spec-containing kind
//     that references `ServiceAccount/NS/Name`, add edge from the SA
//     provider (if any) to the referencing component.
//
// The rules are conservative: an edge is only added when the target
// of the reference is another component in the same graph. Objects
// referencing external / pre-existing resources (e.g. a Pod
// referencing a SA in kube-system that no component provides)
// contribute no edge.
//
// STATUS: currently a stub. The shipping graph populates zero
// Manifests (task #12 will backfill each component's YAML list), so
// this function has nothing to walk. Returning nil, nil is
// intentional — it lets the plan() flow work uniformly whether or
// not Manifests are declared. The stub is kept in place so:
//   - task #12 has a single well-known place to hook into once
//     Manifests start populating.
//   - the plan() flow already accounts for structural edges (they
//     just happen to be zero today), so populating Manifests won't
//     require any planner changes.
//   - the Edge log line's "rule" tags already distinguish policy
//     from structural — anyone reading the log after task #12 lands
//     will see the derived edges plainly.
//
// The four rule implementations live below as unexported helpers
// with matching TODO markers; task #12 fills them in.
func deriveStructuralEdges(byName map[string]*Component) ([]Edge, error) {
	// Fast path: no manifests declared anywhere → no structural
	// edges possible.
	anyManifests := false
	for _, c := range byName {
		if len(c.Manifests) > 0 {
			anyManifests = true
			break
		}
	}
	if !anyManifests {
		return nil, nil
	}

	// TODO(task #12): parse each component's Manifests into a
	// (gvk, namespace, name) inventory, then apply the four rules.
	// For now, populating Manifests is a no-op — the planner still
	// respects PolicyDeps, so components can be migrated one at a
	// time without breaking ordering.
	return nil, nil
}

// TODO(task #12): implement crdToCrEdges, namespaceEdges,
// webhookEdges, serviceAccountEdges. Each returns []Edge with the
// appropriate Rule tag ("crd", "namespace", "webhook", "sa").
