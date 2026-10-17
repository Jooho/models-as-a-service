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

package maas

import (
	"context"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	aigatewayv1alpha1 "github.com/opendatahub-io/ai-gateway-controller/api/aigateway/v1alpha1"
	aiguardrail "github.com/opendatahub-io/ai-gateway-controller/pkg/guardrail"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	maasv1alpha1 "github.com/opendatahub-io/models-as-a-service/maas-controller/api/maas/v1alpha1"
	"github.com/opendatahub-io/models-as-a-service/maas-controller/pkg/platform/tenantreconcile"
)

func TestGuardrailHeaders_ComposesAllAttachmentScopes(t *testing.T) {
	const tenantNamespace = "tenant-a"
	const modelNamespace = "models"

	scheme := runtime.NewScheme()
	if err := maasv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := aigatewayv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	objects := []runtime.Object{
		&maasv1alpha1.AITenant{
			ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Namespace: "ai-tenants"},
			Spec:       maasv1alpha1.AITenantSpec{Guardrails: testGuardrailAttachments("tenant-policy")},
			Status:     maasv1alpha1.AITenantStatus{TenantNamespace: tenantNamespace},
		},
		&maasv1alpha1.MaasTenantConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      maasv1alpha1.MaasTenantConfigInstanceName,
				Namespace: tenantNamespace,
				Annotations: map[string]string{
					tenantreconcile.AnnotationAITenantName:      "tenant-a",
					tenantreconcile.AnnotationAITenantNamespace: "ai-tenants",
				},
			},
			Spec: maasv1alpha1.MaasTenantConfigSpec{Guardrails: testGuardrailAttachments("config-policy")},
		},
		&maasv1alpha1.MaaSSubscription{
			ObjectMeta: metav1.ObjectMeta{Name: "subscription-a", Namespace: tenantNamespace},
			Spec: maasv1alpha1.MaaSSubscriptionSpec{
				Guardrails: testGuardrailAttachments("subscription-policy"),
				ModelRefs: []maasv1alpha1.ModelSubscriptionRef{{
					Name:       "model-a",
					Namespace:  modelNamespace,
					Unlimited:  true,
					Guardrails: testGuardrailAttachments("entry-policy"),
				}},
			},
		},
		&maasv1alpha1.MaaSModelRef{
			ObjectMeta: metav1.ObjectMeta{Name: "model-a", Namespace: modelNamespace},
			Spec:       maasv1alpha1.MaaSModelSpec{Guardrails: testGuardrailAttachments("model-policy")},
			Status:     maasv1alpha1.MaaSModelStatus{ResolvedTenantRef: "tenant-a"},
		},
		testGuardrailPolicy(tenantNamespace, "tenant-policy"),
		testGuardrailPolicy(tenantNamespace, "config-policy"),
		testGuardrailPolicy(tenantNamespace, "subscription-policy"),
		testGuardrailPolicy(tenantNamespace, "entry-policy"),
		testGuardrailPolicy(modelNamespace, "model-policy"),
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	r := &MaaSAuthPolicyReconciler{Client: client}
	headers, err := r.guardrailHeaders(context.Background(), tenantNamespace)
	if err != nil {
		t.Fatalf("guardrailHeaders() error = %v", err)
	}
	if len(headers) != 5 {
		t.Fatalf("guardrailHeaders() returned %d headers, want 5: %#v", len(headers), headers)
	}
	for _, header := range headers {
		if !strings.HasPrefix(header.Name, guardrailHeaderPrefix) {
			t.Fatalf("header name %q does not use the reserved prefix", header.Name)
		}
		if len(header.ID) != 64 {
			t.Fatalf("check ID %q has length %d, want 64", header.ID, len(header.ID))
		}
	}
}

func TestGatewayAuthPolicySpec_AddsSelectedGuardrailHeaders(t *testing.T) {
	r := &MaaSAuthPolicyReconciler{}
	checkID := aiguardrail.CheckID("tenant-a", "privacy", "pii")
	spec := r.buildGatewayAuthPolicySpec(nil, false, "", "models-as-a-service", "gateway-ns", "gateway", []guardrailHeader{{
		ID:   checkID,
		Name: aiguardrail.CheckHeaderName("tenant-a", "privacy", "pii"),
	}})

	obj := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	headers := nestedMapRequired(t, obj, "spec", "defaults", "rules", "response", "success", "headers")
	headerName := aiguardrail.CheckHeaderName("tenant-a", "privacy", "pii")
	expression := nestedStringRequired(t, &unstructured.Unstructured{Object: map[string]any{"header": headers[headerName]}}, "header", "plain", "expression")
	if !strings.Contains(expression, `selectedGuardrailChecks`) || !strings.Contains(expression, checkID) {
		t.Fatalf("guardrail expression does not read the selected check map: %q", expression)
	}
}

func TestSelectedGuardrailHeader_UsesSelectedCheckMap(t *testing.T) {
	checkID := aiguardrail.CheckID("tenant-a", "privacy", "pii")
	header := selectedGuardrailHeader(checkID)
	plain, ok := header["plain"].(map[string]any)
	if !ok {
		t.Fatal("selected guardrail header is missing the plain expression")
	}
	expression, ok := plain["expression"].(string)
	if !ok {
		t.Fatal("selected guardrail header has no CEL expression")
	}
	env, err := cel.NewEnv(cel.Variable("auth", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile(expression)
	if issues.Err() != nil {
		t.Fatalf("Compile: %v", issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		auth map[string]any
		want string
	}{
		{name: "selected", auth: map[string]any{"metadata": map[string]any{"subscription-info": map[string]any{"selectedGuardrailChecks": map[string]bool{checkID: true}}}}, want: "true"},
		{name: "not selected", auth: map[string]any{"metadata": map[string]any{"subscription-info": map[string]any{"selectedGuardrailChecks": map[string]bool{}}}}, want: "false"},
		{name: "selection missing", auth: map[string]any{"metadata": map[string]any{"subscription-info": map[string]any{}}}, want: "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := program.Eval(map[string]any{"auth": tc.auth})
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			if got := out.Value(); got != tc.want {
				t.Fatalf("value = %#v, want %q", got, tc.want)
			}
		})
	}
}

func testGuardrailAttachments(policy string) []maasv1alpha1.GuardrailAttachment {
	return []maasv1alpha1.GuardrailAttachment{{Ref: maasv1alpha1.GuardrailRef{Name: policy}}}
}

func testGuardrailPolicy(namespace, name string) *aigatewayv1alpha1.AIGuardrail {
	return &aigatewayv1alpha1.AIGuardrail{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Generation: 1},
		Spec: aigatewayv1alpha1.AIGuardrailSpec{Checks: []aigatewayv1alpha1.AIGuardrailCheck{{
			Name: "pii", Phases: []aigatewayv1alpha1.GuardrailPhase{aigatewayv1alpha1.GuardrailPhaseInput},
		}}},
		Status: aigatewayv1alpha1.AIGuardrailStatus{
			BindingRevision: "ready",
			Conditions: []metav1.Condition{{
				Type: "Accepted", Status: metav1.ConditionTrue, ObservedGeneration: 1,
			}},
		},
	}
}
