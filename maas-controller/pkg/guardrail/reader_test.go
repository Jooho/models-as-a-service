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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newGuardrailScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

func sampleAIGuardrail() *aigatewayv1alpha1.AIGuardrail {
	return &aigatewayv1alpha1.AIGuardrail{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  targetNS,
			Name:       "safety",
			UID:        types.UID("uid-1"),
			Generation: 3,
		},
		Spec: aigatewayv1alpha1.AIGuardrailSpec{
			Checks: []aigatewayv1alpha1.AIGuardrailCheck{
				{Name: "toxicity", ConfigID: "cfg-tox", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput}},
				{Name: "pii", ConfigID: "cfg-pii", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput, aigatewayv1alpha1.GuardrailPhaseOutput}},
			},
		},
		Status: aigatewayv1alpha1.AIGuardrailStatus{
			ObservedGeneration: 3,
			BindingRevision:    "binding-revision-1",
			Conditions: []metav1.Condition{
				{Type: ConditionAccepted, Status: metav1.ConditionTrue, ObservedGeneration: 3, Reason: "PolicyAccepted"},
			},
		},
	}
}

func TestClientReader_GetPolicy_Found(t *testing.T) {
	scheme := newGuardrailScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sampleAIGuardrail()).Build()
	reader := NewPolicyReader(c)

	got, err := reader.GetPolicy(context.Background(), targetNS, "safety")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := &Policy{
		Namespace:       targetNS,
		Name:            "safety",
		UID:             types.UID("uid-1"),
		Generation:      3,
		BindingRevision: "binding-revision-1",
		Conditions: []PolicyCondition{
			{Type: ConditionAccepted, Status: true, ObservedGeneration: 3},
		},
		Checks: []Check{
			{Name: "toxicity", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput}},
			{Name: "pii", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput, aigatewayv1alpha1.GuardrailPhaseOutput}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("projection mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestClientReader_GetPolicy_NotFound(t *testing.T) {
	scheme := newGuardrailScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reader := NewPolicyReader(c)

	_, err := reader.GetPolicy(context.Background(), targetNS, "safety")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("got error %v, want errors.Is %v", err, ErrPolicyNotFound)
	}
}

func TestClientReader_GetPolicy_NoCrossNamespaceFallback(t *testing.T) {
	scheme := newGuardrailScheme(t)
	other := sampleAIGuardrail()
	other.Namespace = "other-ns"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(other).Build()
	reader := NewPolicyReader(c)

	_, err := reader.GetPolicy(context.Background(), targetNS, "safety")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("got error %v, want errors.Is %v (no cross-namespace fallback)", err, ErrPolicyNotFound)
	}
}

func TestClientReader_GetPolicy_ReadFailure(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build()
	reader := NewPolicyReader(c)

	_, err := reader.GetPolicy(context.Background(), targetNS, "safety")
	if !errors.Is(err, ErrReadFailure) {
		t.Fatalf("got error %v, want errors.Is %v", err, ErrReadFailure)
	}
}

func TestPolicyFromAIGuardrail_DeepCopiesPhases(t *testing.T) {
	src := sampleAIGuardrail()
	policy := policyFromAIGuardrail(src)

	policy.Checks[0].Phases[0] = aigatewayv1alpha1.GuardrailPhaseOutput

	if src.Spec.Checks[0].Phases[0] != aigatewayv1alpha1.GuardrailPhaseInput {
		t.Errorf("mutating projection changed source AIGuardrail phase: %v", src.Spec.Checks[0].Phases[0])
	}
}

func TestClientReader_WithResolver_ConditionUnknown(t *testing.T) {
	scheme := newGuardrailScheme(t)
	g := sampleAIGuardrail()
	g.Status.Conditions[0].Status = metav1.ConditionUnknown
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(g).Build()

	r := NewAttachmentResolver(NewPolicyReader(c))
	_, err := r.Resolve(context.Background(), targetNS, attachment("safety"))
	if !errors.Is(err, ErrNotAccepted) {
		t.Fatalf("got error %v, want errors.Is %v", err, ErrNotAccepted)
	}
}

func TestClientReader_WithResolver(t *testing.T) {
	scheme := newGuardrailScheme(t)
	g := sampleAIGuardrail()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(g).Build()

	r := NewAttachmentResolver(NewPolicyReader(c))
	got, err := r.Resolve(context.Background(), targetNS, attachment("safety", "pii"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UID != types.UID("uid-1") || got.Generation != 3 || got.BindingRevision != "binding-revision-1" {
		t.Errorf("identity mismatch: %+v", got)
	}
	if len(got.Checks) != 1 || got.Checks[0].Name != "pii" {
		t.Errorf("checks mismatch: %+v", got.Checks)
	}
}
