/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package guardrail resolves MaaSSubscription guardrail attachments against the
// referenced AIGuardrail in the accepted tenant namespace.
//
// It fails closed: a missing or unaccepted policy, or an unknown check, is an
// error, not an empty selection. A same-named policy in another namespace is not
// a fallback.
package guardrail

import (
	"context"
	"errors"
	"fmt"

	aigatewayv1alpha1 "github.com/opendatahub-io/ai-gateway-controller/api/aigateway/v1alpha1"
	"k8s.io/apimachinery/pkg/types"

	maasv1alpha1 "github.com/opendatahub-io/models-as-a-service/maas-controller/api/maas/v1alpha1"
)

// Condition types evaluated by the resolver.
const (
	ConditionAccepted     = "Accepted"
	ConditionResolvedRefs = "ResolvedRefs"
)

var (
	// ErrPolicyNotFound: no AIGuardrail with that name in the tenant namespace.
	ErrPolicyNotFound = errors.New("guardrail policy not found")
	// ErrReadFailure: the lookup failed for a reason other than absence.
	ErrReadFailure = errors.New("guardrail policy read failed")
	// ErrNotAccepted: a required condition is missing or not True for the current generation.
	ErrNotAccepted = errors.New("guardrail policy not accepted")
	// ErrStaleGeneration: a condition does not report the current generation.
	ErrStaleGeneration = errors.New("guardrail policy status is stale")
	// ErrUnknownCheck: a requested check name is not in the policy.
	ErrUnknownCheck = errors.New("guardrail check not found in policy")
	// ErrDuplicateCheck: the same check name is requested twice.
	ErrDuplicateCheck = errors.New("guardrail check requested more than once")
)

// Check is a policy check and its request phases.
type Check struct {
	Name   string
	Phases []aigatewayv1alpha1.GuardrailPhase
}

// Policy is the AIGuardrail data the resolver needs.
type Policy struct {
	Namespace  string
	Name       string
	UID        types.UID
	Generation int64
	// Conditions holds the status conditions used to decide acceptance.
	Conditions []PolicyCondition
	// Checks holds every check in the policy spec, in spec order.
	Checks []Check
}

// PolicyCondition is the subset of a status condition the resolver evaluates.
type PolicyCondition struct {
	Type               string
	Status             bool
	ObservedGeneration int64
}

// ResolvedPolicy is the resolver output: the policy identity and the selected
// checks, in spec order.
type ResolvedPolicy struct {
	Namespace  string
	Name       string
	UID        types.UID
	Generation int64
	Checks     []Check
}

// PolicyReader looks up an AIGuardrail by namespace and name. It reads the given
// namespace only, with no fallback: a missing policy returns ErrPolicyNotFound,
// any other failure ErrReadFailure. On success it returns a non-nil Policy,
// never (nil, nil).
type PolicyReader interface {
	GetPolicy(ctx context.Context, namespace, name string) (*Policy, error)
}

// AttachmentResolver resolves guardrail attachments using a PolicyReader.
type AttachmentResolver struct {
	reader PolicyReader
}

// NewAttachmentResolver returns an AttachmentResolver backed by reader.
func NewAttachmentResolver(reader PolicyReader) *AttachmentResolver {
	return &AttachmentResolver{reader: reader}
}

// Resolve resolves a guardrail attachment in targetNamespace.
func (r *AttachmentResolver) Resolve(ctx context.Context, targetNamespace string, att maasv1alpha1.GuardrailAttachment) (*ResolvedPolicy, error) {
	policy, err := r.reader.GetPolicy(ctx, targetNamespace, att.Ref.Name)
	if err != nil {
		return nil, err
	}

	if err := checkAccepted(policy); err != nil {
		return nil, err
	}

	selected, err := selectChecks(policy, att.Checks)
	if err != nil {
		return nil, err
	}

	return &ResolvedPolicy{
		Namespace:  policy.Namespace,
		Name:       policy.Name,
		UID:        policy.UID,
		Generation: policy.Generation,
		Checks:     selected,
	}, nil
}

// ResolveAll resolves every attachment in order.
func (r *AttachmentResolver) ResolveAll(ctx context.Context, targetNamespace string, atts []maasv1alpha1.GuardrailAttachment) ([]ResolvedPolicy, error) {
	out := make([]ResolvedPolicy, 0, len(atts))
	for i := range atts {
		resolved, err := r.Resolve(ctx, targetNamespace, atts[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *resolved)
	}
	return out, nil
}

// checkAccepted verifies the required conditions for the current generation.
func checkAccepted(policy *Policy) error {
	for _, condType := range []string{ConditionAccepted, ConditionResolvedRefs} {
		cond := findCondition(policy.Conditions, condType)
		if cond == nil {
			return fmt.Errorf("policy %q condition %q is not True: %w", policy.Name, condType, ErrNotAccepted)
		}
		if cond.ObservedGeneration != policy.Generation {
			return fmt.Errorf("policy %q condition %q observedGeneration %d does not match generation %d: %w",
				policy.Name, condType, cond.ObservedGeneration, policy.Generation, ErrStaleGeneration)
		}
		if !cond.Status {
			return fmt.Errorf("policy %q condition %q is not True: %w", policy.Name, condType, ErrNotAccepted)
		}
	}
	return nil
}

func findCondition(conditions []PolicyCondition, condType string) *PolicyCondition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

// selectChecks expands an empty selection or validates an explicit one.
func selectChecks(policy *Policy, requested []string) ([]Check, error) {
	if len(requested) == 0 {
		return copyChecks(policy.Checks), nil
	}

	available := make(map[string]struct{}, len(policy.Checks))
	for _, c := range policy.Checks {
		available[c.Name] = struct{}{}
	}

	wanted := make(map[string]struct{}, len(requested))
	for _, name := range requested {
		if _, ok := available[name]; !ok {
			return nil, fmt.Errorf("policy %q does not define check %q: %w", policy.Name, name, ErrUnknownCheck)
		}
		if _, dup := wanted[name]; dup {
			return nil, fmt.Errorf("policy %q check %q requested more than once: %w", policy.Name, name, ErrDuplicateCheck)
		}
		wanted[name] = struct{}{}
	}
	selected := make([]Check, 0, len(requested))
	for _, c := range policy.Checks {
		if _, ok := wanted[c.Name]; ok {
			selected = append(selected, cloneCheck(c))
		}
	}
	return selected, nil
}

func copyChecks(checks []Check) []Check {
	out := make([]Check, 0, len(checks))
	for _, c := range checks {
		out = append(out, cloneCheck(c))
	}
	return out
}

// cloneCheck returns a check with an independent phases slice.
func cloneCheck(c Check) Check {
	phases := make([]aigatewayv1alpha1.GuardrailPhase, len(c.Phases))
	copy(phases, c.Phases)
	return Check{Name: c.Name, Phases: phases}
}
