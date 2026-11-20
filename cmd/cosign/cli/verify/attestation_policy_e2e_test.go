//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/policy"
	csignature "github.com/sigstore/cosign/v3/pkg/signature"
	sgsign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
)

// testAttestationEnv holds a local registry, a signed image and a signing key.
type testAttestationEnv struct {
	td      string
	img     string
	pubPath string
	ref     name.Digest
	digest  string
	kp      sgsign.Keypair
	server  *httptest.Server
}

func newAttestationEnv(t *testing.T, imageName string) *testAttestationEnv {
	t.Helper()
	r := registry.New(registry.WithReferrersSupport(true))
	s := httptest.NewServer(r)
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	td := t.TempDir()
	img := fmt.Sprintf("%s/%s:latest", u.Host, imageName)
	ref, err := name.ParseReference(img)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, empty.Image); err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Head(ref)
	if err != nil {
		t.Fatal(err)
	}

	kp, err := sgsign.NewEphemeralKeypair(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(kp.GetPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(td, "cosign.pub")
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	return &testAttestationEnv{
		td:      td,
		img:     img,
		pubPath: pubPath,
		ref:     ref.Context().Digest(desc.Digest.String()),
		digest:  strings.TrimPrefix(desc.Digest.String(), "sha256:"),
		kp:      kp,
		server:  s,
	}
}

// stopRegistry shuts down the test registry so the next request fails.
func (e *testAttestationEnv) stopRegistry(t *testing.T) {
	t.Helper()
	e.server.Close()
}

// checkOptsForTest builds the same CheckOpts the command constructs.
func (e *testAttestationEnv) checkOptsForTest(t *testing.T) *cosign.CheckOpts {
	t.Helper()
	sv, err := csignature.PublicKeyFromKeyRef(context.Background(), e.pubPath)
	if err != nil {
		t.Fatal(err)
	}
	return &cosign.CheckOpts{SigVerifier: sv, IgnoreTlog: true, MaxWorkers: 10, NewBundleFormat: true}
}

// writeAttestation signs an in-toto statement with the test key and uploads it
// as a Sigstore bundle referrer, as `cosign attest` does.
func (e *testAttestationEnv) writeAttestation(t *testing.T, predicateType string, predicate any) {
	t.Helper()
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predicateType,
		"subject": []any{map[string]any{
			"name":   e.img,
			"digest": map[string]any{"sha256": e.digest},
		}},
		"predicate": predicate,
	}
	stmtJSON, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	dsse := &sgsign.DSSEData{Data: stmtJSON, PayloadType: "application/vnd.in-toto+json"}
	pb, err := sgsign.Bundle(dsse, e.kp, sgsign.BundleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bundleBytes, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	if err := ociremote.WriteAttestationNewBundleFormat(e.ref, bundleBytes, predicateType); err != nil {
		t.Fatal(err)
	}
}

func (e *testAttestationEnv) command(t *testing.T, policyPath string) *VerifyAttestationCommand {
	t.Helper()
	return &VerifyAttestationCommand{
		CommonVerifyOptions: options.CommonVerifyOptions{NewBundleFormat: true},
		KeyRef:              e.pubPath,
		IgnoreTlog:          true,
		MaxWorkers:          10,
		PredicateType:       "slsaprovenance",
		AttestationPolicy:   policyPath,
		Output:              "json",
	}
}

func (e *testAttestationEnv) writePolicy(t *testing.T, doc string) string {
	t.Helper()
	p := filepath.Join(e.td, "policy.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const provenancePolicy = `
version: "1"
attestations:
  - name: provenance
    predicateType: slsaprovenance
    required: true
    fields:
      - path: buildType
        equals: https://example.com/build/v1
`

// TestAttestationPolicyRejectsIrrelevantContent is the regression test for the
// reported behaviour: a well-formed attestation whose content does not match
// the policy must no longer pass verification.
func TestAttestationPolicyRejectsIrrelevantContent(t *testing.T) {
	env := newAttestationEnv(t, "policy-irrelevant")
	env.writeAttestation(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"buildType": "https://evil.example.net/build",
		"builder":   map[string]any{"id": "https://evil.example.net"},
	})
	policyPath := env.writePolicy(t, provenancePolicy)

	err := env.command(t, policyPath).Exec(context.Background(), []string{env.img})
	if err == nil {
		t.Fatal("verification passed with irrelevant attestation content")
	}
	var failure *policy.PolicyFailure
	if !errors.As(err, &failure) {
		t.Fatalf("expected *policy.PolicyFailure, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "provenance") {
		t.Errorf("failure should name the rule: %v", err)
	}
}

// TestAttestationPolicyAcceptsMatchingContent confirms the same image passes
// once the content matches, so the reject test is not passing for the wrong
// reason.
func TestAttestationPolicyAcceptsMatchingContent(t *testing.T) {
	env := newAttestationEnv(t, "policy-matching")
	env.writeAttestation(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"buildType": "https://example.com/build/v1",
		"builder":   map[string]any{"id": "https://builder.example.com"},
	})
	policyPath := env.writePolicy(t, provenancePolicy)

	if err := env.command(t, policyPath).Exec(context.Background(), []string{env.img}); err != nil {
		t.Fatalf("expected verification to pass: %v", err)
	}
}

// TestAttestationPolicyMissingTypeIsNamed asserts a missing required type
// produces a specific, actionable error.
func TestAttestationPolicyMissingTypeIsNamed(t *testing.T) {
	env := newAttestationEnv(t, "policy-missing")
	env.writeAttestation(t, "https://cyclonedx.org/bom", map[string]any{"specVersion": "1.5"})
	policyPath := env.writePolicy(t, provenancePolicy)

	err := env.command(t, policyPath).Exec(context.Background(), []string{env.img})
	if err == nil {
		t.Fatal("expected verification to fail when the required type is absent")
	}
	if !strings.Contains(err.Error(), "missing required attestations") || !strings.Contains(err.Error(), "provenance") {
		t.Fatalf("error should name the missing attestation: %v", err)
	}
}

// TestAttestationPolicyMultipleTypes checks that several attestations of
// different types are each judged, rather than only the first being consulted.
func TestAttestationPolicyMultipleTypes(t *testing.T) {
	env := newAttestationEnv(t, "policy-multi")
	env.writeAttestation(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"buildType": "https://example.com/build/v1",
	})
	env.writeAttestation(t, "https://cyclonedx.org/bom", map[string]any{
		"specVersion": "1.4", // policy requires 1.5
	})
	policyPath := env.writePolicy(t, `
version: "1"
attestations:
  - name: provenance
    predicateType: slsaprovenance
    fields:
      - path: buildType
        equals: https://example.com/build/v1
  - name: sbom
    predicateType: cyclonedx
    fields:
      - path: specVersion
        equals: "1.5"
`)

	err := env.command(t, policyPath).Exec(context.Background(), []string{env.img})
	if err == nil {
		t.Fatal("expected failure because the SBOM version is wrong")
	}
	if !strings.Contains(err.Error(), "sbom") {
		t.Errorf("failure should identify the failing rule: %v", err)
	}
	if strings.Contains(err.Error(), "provenance") {
		t.Errorf("provenance should have passed: %v", err)
	}
}

// TestAttestationPolicyFetchFailureIsDistinct asserts that a missing image is
// reported as such rather than as a fetch failure or a policy pass.
func TestAttestationPolicyFetchFailureIsDistinct(t *testing.T) {
	env := newAttestationEnv(t, "policy-fetch")
	bogus := strings.Replace(env.img, ":latest", ":does-not-exist", 1)
	err := env.command(t, env.writePolicy(t, provenancePolicy)).Exec(context.Background(), []string{bogus})
	if err == nil {
		t.Fatal("expected an error for a missing image tag")
	}
	var tagNotFound *cosign.ErrImageTagNotFound
	if !errors.As(err, &tagNotFound) {
		t.Fatalf("expected ErrImageTagNotFound, got %T: %v", err, err)
	}
}

// TestAttestationPolicyUnparseablePolicyIsRejected asserts a broken policy
// document refuses verification instead of defaulting to allow.
func TestAttestationPolicyUnparseablePolicyIsRejected(t *testing.T) {
	env := newAttestationEnv(t, "policy-broken")
	env.writeAttestation(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"buildType": "https://example.com/build/v1",
	})
	broken := env.writePolicy(t, "attestations:\n  - predicateType: slsaprovenance\n    unknownField: 1\n")

	err := env.command(t, broken).Exec(context.Background(), []string{env.img})
	if err == nil {
		t.Fatal("a broken policy must not verify")
	}
	var perr *policy.PolicyParseError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *policy.PolicyParseError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "policy.yaml") {
		t.Errorf("error should name the policy file: %v", err)
	}
}

// TestAttestationPolicyDisabledKeepsLegacyBehaviour asserts that without the
// new flag, an attestation with non-matching content still verifies exactly as
// before (the flag is purely additive).
func TestAttestationPolicyDisabledKeepsLegacyBehaviour(t *testing.T) {
	env := newAttestationEnv(t, "policy-legacy")
	env.writeAttestation(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"buildType": "https://evil.example.net/build",
	})
	cmd := env.command(t, "")
	cmd.PredicateType = "slsaprovenance"

	if err := cmd.Exec(context.Background(), []string{env.img}); err != nil {
		t.Fatalf("with no attestation policy set, legacy verification should still pass: %v", err)
	}
}

// TestAttestationPolicyNoAttestationsNamesMissingType asserts that an image
// with no attestations is judged by the policy (and names the missing type),
// rather than short-circuiting with a generic "no attestations" error.
func TestAttestationPolicyNoAttestationsNamesMissingType(t *testing.T) {
	env := newAttestationEnv(t, "policy-none")
	policyPath := env.writePolicy(t, provenancePolicy)

	err := env.command(t, policyPath).Exec(context.Background(), []string{env.img})
	if err == nil {
		t.Fatal("expected failure when the image has no attestations")
	}
	if !strings.Contains(err.Error(), "missing required attestations") || !strings.Contains(err.Error(), "provenance") {
		t.Fatalf("error should name the missing attestation type: %v", err)
	}
}

// TestAttestationPolicyJSONReportShape asserts the emitted report is valid
// JSON, digest-addressed and free of raw predicate values.
func TestAttestationPolicyJSONReportShape(t *testing.T) {
	env := newAttestationEnv(t, "policy-report")
	env.writeAttestation(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"buildType": "https://example.com/build/v1",
	})
	policyPath := env.writePolicy(t, provenancePolicy)

	evidence, err := fetchAndVerifyAttestations(context.Background(), env.img, env.checkOptsForTest(t), false, nil, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	report, err := evaluateAttestationReport(specForTest(t, policyPath), evidence)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	for _, key := range []string{"version", "passed", "rules", "results", "bySigner"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("report is missing %q", key)
		}
	}
	results, ok := decoded["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("expected one per-attestation result, got %v", decoded["results"])
	}
	res := results[0].(map[string]any)
	if digest, _ := res["digest"].(string); !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("result digest = %v, want sha256:...", res["digest"])
	}
	if strings.Contains(string(raw), "example.com/build/v1") {
		t.Errorf("report leaked a predicate value: %s", raw)
	}
}

func specForTest(t *testing.T, path string) *policy.PolicySpec {
	t.Helper()
	spec, err := policy.ParsePolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
