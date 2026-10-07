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

package guardrail

import (
	"context"
	"errors"
	"reflect"
	"testing"

	aigatewayv1alpha1 "github.com/opendatahub-io/ai-gateway-controller/api/aigateway/v1alpha1"
	"k8s.io/apimachinery/pkg/types"

	maasv1alpha1 "github.com/opendatahub-io/models-as-a-service/maas-controller/api/maas/v1alpha1"
)

const targetNS = "tenant-ns"

type fakeReader struct {
	policy *Policy
	err    error

	gotNamespace string
	gotName      string
}

func (f *fakeReader) GetPolicy(_ context.Context, namespace, name string) (*Policy, error) {
	f.gotNamespace = namespace
	f.gotName = name
	if f.err != nil {
		return nil, f.err
	}
	return f.policy, nil
}

func acceptedCond(condType string, gen int64) PolicyCondition {
	return PolicyCondition{Type: condType, Status: true, ObservedGeneration: gen}
}

func acceptedPolicy() *Policy {
	return &Policy{
		Namespace:  targetNS,
		Name:       "safety",
		UID:        types.UID("uid-1"),
		Generation: 2,
		Conditions: []PolicyCondition{
			acceptedCond(ConditionAccepted, 2),
			acceptedCond(ConditionResolvedRefs, 2),
		},
		Checks: []Check{
			{Name: "toxicity", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput}},
			{Name: "pii", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput, aigatewayv1alpha1.GuardrailPhaseOutput}},
		},
	}
}

func attachment(name string, checks ...string) maasv1alpha1.GuardrailAttachment {
	return maasv1alpha1.GuardrailAttachment{
		Ref:    maasv1alpha1.GuardrailRef{Name: name},
		Checks: checks,
	}
}

func TestResolver_Resolve(t *testing.T) {
	tests := []struct {
		name       string
		policy     *Policy
		readerErr  error
		attachment maasv1alpha1.GuardrailAttachment
		wantChecks []Check
		wantErr    error
	}{
		{
			name:       "explicit subset",
			policy:     acceptedPolicy(),
			attachment: attachment("safety", "pii"),
			wantChecks: []Check{
				{Name: "pii", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput, aigatewayv1alpha1.GuardrailPhaseOutput}},
			},
		},
		{
			name:       "explicit selection keeps spec order not request order",
			policy:     acceptedPolicy(),
			attachment: attachment("safety", "pii", "toxicity"),
			wantChecks: []Check{
				{Name: "toxicity", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput}},
				{Name: "pii", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput, aigatewayv1alpha1.GuardrailPhaseOutput}},
			},
		},
		{
			name:       "omitted checks selects all",
			policy:     acceptedPolicy(),
			attachment: attachment("safety"),
			wantChecks: acceptedPolicy().Checks,
		},
		{
			name:       "empty checks selects all",
			policy:     acceptedPolicy(),
			attachment: maasv1alpha1.GuardrailAttachment{Ref: maasv1alpha1.GuardrailRef{Name: "safety"}, Checks: []string{}},
			wantChecks: acceptedPolicy().Checks,
		},
		{
			name:       "missing policy",
			readerErr:  ErrPolicyNotFound,
			attachment: attachment("safety"),
			wantErr:    ErrPolicyNotFound,
		},
		{
			name:       "read failure",
			readerErr:  ErrReadFailure,
			attachment: attachment("safety"),
			wantErr:    ErrReadFailure,
		},
		{
			name:       "unknown check",
			policy:     acceptedPolicy(),
			attachment: attachment("safety", "nope"),
			wantErr:    ErrUnknownCheck,
		},
		{
			name:       "duplicate check name rejected",
			policy:     acceptedPolicy(),
			attachment: attachment("safety", "pii", "pii"),
			wantErr:    ErrDuplicateCheck,
		},
		{
			name: "accepted condition missing",
			policy: func() *Policy {
				p := acceptedPolicy()
				p.Conditions = []PolicyCondition{acceptedCond(ConditionResolvedRefs, 2)}
				return p
			}(),
			attachment: attachment("safety"),
			wantErr:    ErrNotAccepted,
		},
		{
			name: "accepted condition false",
			policy: func() *Policy {
				p := acceptedPolicy()
				p.Conditions[0].Status = false
				return p
			}(),
			attachment: attachment("safety"),
			wantErr:    ErrNotAccepted,
		},
		{
			name: "resolvedrefs condition missing",
			policy: func() *Policy {
				p := acceptedPolicy()
				p.Conditions = []PolicyCondition{acceptedCond(ConditionAccepted, 2)}
				return p
			}(),
			attachment: attachment("safety"),
			wantErr:    ErrNotAccepted,
		},
		{
			name: "stale generation on accepted",
			policy: func() *Policy {
				p := acceptedPolicy()
				p.Conditions[0].ObservedGeneration = 1
				return p
			}(),
			attachment: attachment("safety"),
			wantErr:    ErrStaleGeneration,
		},
		{
			name: "stale generation takes precedence over false status",
			policy: func() *Policy {
				p := acceptedPolicy()
				p.Conditions[0].Status = false
				p.Conditions[0].ObservedGeneration = 1
				return p
			}(),
			attachment: attachment("safety"),
			wantErr:    ErrStaleGeneration,
		},
		{
			name: "stale generation on resolvedrefs",
			policy: func() *Policy {
				p := acceptedPolicy()
				p.Conditions[1].ObservedGeneration = 1
				return p
			}(),
			attachment: attachment("safety"),
			wantErr:    ErrStaleGeneration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &fakeReader{policy: tt.policy, err: tt.readerErr}
			r := NewAttachmentResolver(reader)

			got, err := r.Resolve(context.Background(), targetNS, tt.attachment)

			// The resolver must look the policy up by the attachment ref name in
			// the target namespace only, with no fallback.
			if reader.gotNamespace != targetNS {
				t.Errorf("read namespace = %q, want %q", reader.gotNamespace, targetNS)
			}
			if reader.gotName != tt.attachment.Ref.Name {
				t.Errorf("read name = %q, want %q", reader.gotName, tt.attachment.Ref.Name)
			}

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("got error %v, want errors.Is %v", err, tt.wantErr)
				}
				if got != nil {
					t.Fatalf("got non-nil result %+v on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Namespace != tt.policy.Namespace || got.Name != tt.policy.Name ||
				got.UID != tt.policy.UID || got.Generation != tt.policy.Generation {
				t.Errorf("identity mismatch: got %+v, want ns=%s name=%s uid=%s gen=%d",
					got, tt.policy.Namespace, tt.policy.Name, tt.policy.UID, tt.policy.Generation)
			}
			if !reflect.DeepEqual(got.Checks, tt.wantChecks) {
				t.Errorf("checks mismatch:\n got %+v\nwant %+v", got.Checks, tt.wantChecks)
			}
		})
	}
}

func TestResolver_DoesNotMutateSource(t *testing.T) {
	policy := acceptedPolicy()
	snapshot := acceptedPolicy()
	reader := &fakeReader{policy: policy}
	r := NewAttachmentResolver(reader)

	got, err := r.Resolve(context.Background(), targetNS, attachment("safety", "pii"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got.Checks[0].Phases[0] = aigatewayv1alpha1.GuardrailPhaseOutput
	if !reflect.DeepEqual(policy.Checks, snapshot.Checks) {
		t.Errorf("source policy checks mutated:\n got %+v\nwant %+v", policy.Checks, snapshot.Checks)
	}
}

func TestResolver_ResolveAll(t *testing.T) {
	reader := &fakeReader{policy: acceptedPolicy()}
	r := NewAttachmentResolver(reader)

	out, err := r.ResolveAll(context.Background(), targetNS, []maasv1alpha1.GuardrailAttachment{
		attachment("safety", "pii"),
		attachment("safety"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d resolved policies, want 2", len(out))
	}
	if len(out[0].Checks) != 1 || len(out[1].Checks) != 2 {
		t.Errorf("unexpected check counts: %d, %d", len(out[0].Checks), len(out[1].Checks))
	}
}

// byNameReader returns a policy for known names and ErrPolicyNotFound otherwise.
type byNameReader struct {
	policies map[string]*Policy
}

func (b *byNameReader) GetPolicy(_ context.Context, _, name string) (*Policy, error) {
	if p, ok := b.policies[name]; ok {
		return p, nil
	}
	return nil, ErrPolicyNotFound
}

// TestResolver_ResolveAllStopsOnError checks that a failing attachment makes
// ResolveAll return nil and the error, whether it is the first or a later one.
func TestResolver_ResolveAllStopsOnError(t *testing.T) {
	tests := []struct {
		name        string
		attachments []maasv1alpha1.GuardrailAttachment
	}{
		{
			name:        "first attachment fails",
			attachments: []maasv1alpha1.GuardrailAttachment{attachment("missing"), attachment("safety")},
		},
		{
			name:        "later attachment fails",
			attachments: []maasv1alpha1.GuardrailAttachment{attachment("safety"), attachment("missing")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &byNameReader{policies: map[string]*Policy{"safety": acceptedPolicy()}}
			r := NewAttachmentResolver(reader)

			out, err := r.ResolveAll(context.Background(), targetNS, tt.attachments)
			if !errors.Is(err, ErrPolicyNotFound) {
				t.Fatalf("got error %v, want errors.Is %v", err, ErrPolicyNotFound)
			}
			if out != nil {
				t.Errorf("got partial result %+v, want nil", out)
			}
		})
	}
}
