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
	"fmt"

	aigatewayv1alpha1 "github.com/opendatahub-io/ai-gateway-controller/api/aigateway/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AddToScheme registers AIGuardrail API types.
func AddToScheme(s *runtime.Scheme) error {
	return aigatewayv1alpha1.AddToScheme(s)
}

// ClientPolicyReader reads AIGuardrail policies through a controller-runtime
// client. It satisfies PolicyReader.
type ClientPolicyReader struct {
	client client.Reader
}

// NewPolicyReader returns a ClientPolicyReader backed by c.
func NewPolicyReader(c client.Reader) *ClientPolicyReader {
	return &ClientPolicyReader{client: c}
}

// GetPolicy reads an AIGuardrail and projects it to a Policy.
func (r *ClientPolicyReader) GetPolicy(ctx context.Context, namespace, name string) (*Policy, error) {
	var g aigatewayv1alpha1.AIGuardrail
	key := types.NamespacedName{Namespace: namespace, Name: name}
	if err := r.client.Get(ctx, key, &g); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("%s/%s: %w", namespace, name, ErrPolicyNotFound)
		}
		return nil, fmt.Errorf("%s/%s: %w: %w", namespace, name, ErrReadFailure, err)
	}
	return policyFromAIGuardrail(&g), nil
}

// policyFromAIGuardrail projects an AIGuardrail into a Policy.
func policyFromAIGuardrail(g *aigatewayv1alpha1.AIGuardrail) *Policy {
	checks := make([]Check, 0, len(g.Spec.Checks))
	for _, c := range g.Spec.Checks {
		phases := make([]aigatewayv1alpha1.GuardrailPhase, len(c.Phases))
		copy(phases, c.Phases)
		checks = append(checks, Check{Name: c.Name, Phases: phases})
	}

	conditions := make([]PolicyCondition, 0, len(g.Status.Conditions))
	for _, c := range g.Status.Conditions {
		conditions = append(conditions, PolicyCondition{
			Type:               c.Type,
			Status:             c.Status == metav1.ConditionTrue,
			ObservedGeneration: c.ObservedGeneration,
		})
	}

	return &Policy{
		Namespace:       g.Namespace,
		Name:            g.Name,
		UID:             g.UID,
		Generation:      g.Generation,
		BindingRevision: g.Status.BindingRevision,
		Conditions:      conditions,
		Checks:          checks,
	}
}
