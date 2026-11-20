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

package policy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// makeEnvelope builds a DSSE envelope whose payload is the given in-toto
// statement. It mirrors what a registry stores, without any signature, because
// these tests exercise content evaluation only.
func makeEnvelope(t *testing.T, predicateType string, predicate any) []byte {
	t.Helper()
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": predicateType,
		"subject": []any{
			map[string]any{
				"name":   "example.com/repo",
				"digest": map[string]any{"sha256": strings.Repeat("a", 64)},
			},
		},
		"predicate": predicate,
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

const testPolicy = `
version: "1"
attestations:
  - name: provenance
    predicateType: slsaprovenance
    required: true
    fields:
      - path: builder.id
        matches: "^https://builder\\.example\\.com/"
      - path: buildType
        equals: https://example.com/build/v1
  - name: sbom
    predicateType: cyclonedx
    required: true
    minCount: 1
    fields:
      - path: specVersion
        equals: "1.5"
`

func mustParse(t *testing.T, doc string) *PolicySpec {
	t.Helper()
	spec, err := ParsePolicy([]byte(doc), "test-policy.yaml")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return spec
}

func TestEvaluateSelectsByDeclaredType(t *testing.T) {
	spec := mustParse(t, testPolicy)
	inputs := []AttestationInput{
		{Envelope: makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
			"builder":   map[string]any{"id": "https://builder.example.com/ci"},
			"buildType": "https://example.com/build/v1",
		})},
		// A differently typed attestation that happens to carry matching fields
		// must not be selected.
		{Envelope: makeEnvelope(t, "https://example.com/other/v1", map[string]any{
			"builder":   map[string]any{"id": "https://builder.example.com/ci"},
			"buildType": "https://example.com/build/v1",
		})},
		{Envelope: makeEnvelope(t, "https://cyclonedx.org/bom", map[string]any{"specVersion": "1.5"})},
	}
	report := Evaluate(spec, inputs)

	if report.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", report.Skipped)
	}
	if !report.Passed {
		t.Errorf("expected policy to pass, unmet=%v missing=%v", report.UnmetRules, report.MissingRules)
	}
	if got := report.Rules[0].Matched; got != 1 {
		t.Errorf("provenance matched = %d, want 1", got)
	}
	selected := 0
	for _, r := range report.Results {
		if r.Selected {
			selected++
		}
	}
	if selected != 2 {
		t.Errorf("selected = %d, want 2 (provenance and sbom): %+v", selected, report.Results)
	}
	for i := 1; i < len(report.Results); i++ {
		if report.Results[i-1].Digest > report.Results[i].Digest {
			t.Errorf("results must be sorted by digest: %+v", report.Results)
		}
	}
}

func TestEvaluateMultipleTypesJudgedIndependently(t *testing.T) {
	spec := mustParse(t, testPolicy)
	inputs := []AttestationInput{
		{Envelope: makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
			"builder":   map[string]any{"id": "https://builder.example.com/ci"},
			"buildType": "https://example.com/build/v1",
		})},
		{Envelope: makeEnvelope(t, "https://cyclonedx.org/bom", map[string]any{
			"specVersion": "1.5",
			"components":  []any{},
		})},
	}
	report := Evaluate(spec, inputs)
	if !report.Passed {
		t.Fatalf("expected both rules to pass: %+v", report.Rules)
	}
	for _, r := range report.Rules {
		if !r.Satisfied || r.Missing {
			t.Errorf("rule %s not satisfied: %+v", r.Name, r)
		}
	}
}

func TestEvaluateMissingTypeNamesTheRule(t *testing.T) {
	spec := mustParse(t, testPolicy)
	inputs := []AttestationInput{
		{Envelope: makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
			"builder":   map[string]any{"id": "https://builder.example.com/ci"},
			"buildType": "https://example.com/build/v1",
		})},
	}
	report := Evaluate(spec, inputs)
	if report.Passed {
		t.Fatal("expected failure when the SBOM attestation is absent")
	}
	if len(report.MissingRules) != 1 || report.MissingRules[0] != "sbom" {
		t.Errorf("MissingRules = %v, want [sbom]", report.MissingRules)
	}
	failure := (&PolicyFailure{Missing: report.MissingRules, Unmet: report.UnmetRules}).Error()
	if !strings.Contains(failure, "sbom") || !strings.Contains(failure, "missing required attestations") {
		t.Errorf("failure message does not name the missing rule: %s", failure)
	}
}

func TestEvaluateFieldMismatchReportsPath(t *testing.T) {
	spec := mustParse(t, testPolicy)
	inputs := []AttestationInput{
		{Envelope: makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
			"builder":   map[string]any{"id": "https://evil.example.net/ci"},
			"buildType": "https://example.com/build/v2",
		})},
		{Envelope: makeEnvelope(t, "https://cyclonedx.org/bom", map[string]any{
			"specVersion": "1.5",
		})},
	}
	report := Evaluate(spec, inputs)
	if report.Passed {
		t.Fatal("expected failure for field mismatches")
	}
	var seen []string
	for _, res := range report.Results {
		for _, rd := range res.Diffs {
			if rd.Rule != "provenance" {
				continue
			}
			for _, f := range rd.Fields {
				seen = append(seen, f.Path)
				if f.ActualSHA256 == "" {
					t.Errorf("field %s should carry a digest of the observed value", f.Path)
				}
			}
		}
	}
	for _, want := range []string{"builder.id", "buildType"} {
		if !contains(seen, want) {
			t.Errorf("expected diff for %q, got %v", want, seen)
		}
	}
	// The report must not leak the observed values.
	for _, res := range report.Results {
		for _, rd := range res.Diffs {
			for _, f := range rd.Fields {
				if s, ok := f.Expected.(string); ok && strings.Contains(s, "evil") {
					t.Errorf("unexpected leaked value in report: %v", s)
				}
			}
		}
	}
}

func TestEvaluateEmptyPredicateFailsNotSkipped(t *testing.T) {
	doc := `
version: "1"
attestations:
  - name: provenance
    predicateType: slsaprovenance
    required: true
    fields:
      - path: builder.id
        present: true
`
	spec := mustParse(t, doc)
	inputs := []AttestationInput{
		{Envelope: makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{})},
	}
	report := Evaluate(spec, inputs)
	if report.Passed {
		t.Fatal("an empty predicate must not pass")
	}
	if report.Rules[0].Missing {
		t.Error("the type was present, so the rule must not be reported as missing")
	}
	if len(report.MissingRules) != 0 {
		t.Errorf("empty content is not a missing type, got %v", report.MissingRules)
	}
	if !contains(report.UnmetRules, "provenance") {
		t.Errorf("UnmetRules = %v, want provenance", report.UnmetRules)
	}
}

func TestEvaluateIsolatesMalformedAttestation(t *testing.T) {
	spec := mustParse(t, testPolicy)
	inputs := []AttestationInput{
		{Envelope: []byte(`{"payload":`)},
		{Envelope: makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
			"builder":   map[string]any{"id": "https://builder.example.com/ci"},
			"buildType": "https://example.com/build/v1",
		})},
		{Envelope: makeEnvelope(t, "https://cyclonedx.org/bom", map[string]any{"specVersion": "1.5"})},
	}
	report := Evaluate(spec, inputs)
	if report.IsolatedErrors != 1 {
		t.Errorf("IsolatedErrors = %d, want 1", report.IsolatedErrors)
	}
	if !report.Passed {
		t.Errorf("the remaining attestations should still pass the policy: %+v", report.UnmetRules)
	}
}

func TestEvaluatePerAttestationResultsMatchBoolean(t *testing.T) {
	// Require two SBOMs so that one good and one bad attestation produce a
	// failing aggregate while both still appear in the per-attestation report.
	spec := mustParse(t, `
version: "1"
attestations:
  - name: provenance
    predicateType: slsaprovenance
    fields:
      - path: buildType
        equals: https://example.com/build/v1
  - name: sbom
    predicateType: cyclonedx
    minCount: 2
    fields:
      - path: specVersion
        equals: "1.5"
`)
	goodProvenance := makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"builder":   map[string]any{"id": "https://builder.example.com/ci"},
		"buildType": "https://example.com/build/v1",
	})
	goodSBOM := makeEnvelope(t, "https://cyclonedx.org/bom", map[string]any{"specVersion": "1.5"})
	badSBOM := makeEnvelope(t, "https://cyclonedx.org/bom", map[string]any{"specVersion": "9.9"})

	// Many attestations: the aggregate boolean must equal the conjunction of
	// the per-rule results, and per-attestation entries must account for all.
	inputs := []AttestationInput{
		{Envelope: goodProvenance},
		{Envelope: goodSBOM},
		{Envelope: badSBOM},
		{Envelope: makeEnvelope(t, "https://example.com/unrelated/v1", map[string]any{"x": 1})},
	}
	report := Evaluate(spec, inputs)

	if len(report.Results) != len(inputs) {
		t.Fatalf("got %d per-attestation results, want %d", len(report.Results), len(inputs))
	}
	allRulesSatisfied := true
	for _, r := range report.Rules {
		if r.Required && !r.Satisfied {
			allRulesSatisfied = false
		}
	}
	if report.Passed != allRulesSatisfied {
		t.Errorf("Passed = %t but per-rule conjunction = %t", report.Passed, allRulesSatisfied)
	}
	if report.Passed {
		t.Error("expected failure: one SBOM has the wrong specVersion")
	}
	if got := report.Rules[1].Present; got != 2 {
		t.Errorf("sbom present = %d, want 2", got)
	}
	if got := report.Rules[1].Matched; got != 1 {
		t.Errorf("sbom matched = %d, want 1", got)
	}
	// Digests are unique and stable per envelope.
	seen := map[string]bool{}
	for _, r := range report.Results {
		if !strings.HasPrefix(r.Digest, "sha256:") {
			t.Errorf("result digest %q is not sha256-addressed", r.Digest)
		}
		if seen[r.Digest] {
			t.Errorf("duplicate digest %s", r.Digest)
		}
		seen[r.Digest] = true
	}
}

func TestEvaluateDeterministic(t *testing.T) {
	spec := mustParse(t, testPolicy)
	inputs := []AttestationInput{
		{Envelope: makeEnvelope(t, "https://cyclonedx.org/bom", map[string]any{"specVersion": "1.5"}), Signer: "b@example.com"},
		{Envelope: makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
			"builder":   map[string]any{"id": "https://builder.example.com/ci"},
			"buildType": "https://example.com/build/v1",
		}), Signer: "a@example.com"},
	}
	first, err := json.Marshal(Evaluate(spec, inputs))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		next, err := json.Marshal(Evaluate(spec, inputs))
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(next) {
			t.Fatalf("evaluation %d is not deterministic:\n%s\n%s", i, first, next)
		}
	}
}

func TestEvaluatePerSignerAttribution(t *testing.T) {
	spec := mustParse(t, testPolicy)
	inputs := []AttestationInput{
		{Envelope: makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
			"builder":   map[string]any{"id": "https://builder.example.com/ci"},
			"buildType": "https://example.com/build/v1",
		}), Signer: "provenance-signer", Issuer: "https://issuer.example.com"},
		{Envelope: makeEnvelope(t, "https://cyclonedx.org/bom", map[string]any{"specVersion": "1.5"}), Signer: "sbom-signer"},
	}
	report := Evaluate(spec, inputs)
	if len(report.BySigner) != 2 {
		t.Fatalf("got %d signers, want 2", len(report.BySigner))
	}
	byName := map[string]SignerResult{}
	for _, s := range report.BySigner {
		byName[s.Signer] = s
	}
	if got := byName["provenance-signer"]; !contains(got.SatisfiedRules, "provenance") || contains(got.SatisfiedRules, "sbom") {
		t.Errorf("provenance-signer attribution wrong: %+v", got)
	}
	if got := byName["sbom-signer"]; !contains(got.SatisfiedRules, "sbom") || contains(got.SatisfiedRules, "provenance") {
		t.Errorf("sbom-signer attribution wrong: %+v", got)
	}
}

func TestEvaluateDoesNotMutateInput(t *testing.T) {
	spec := mustParse(t, testPolicy)
	env := makeEnvelope(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"builder":   map[string]any{"id": "https://builder.example.com/ci"},
		"buildType": "https://example.com/build/v1",
	})
	original := append([]byte(nil), env...)
	Evaluate(spec, []AttestationInput{{Envelope: env}})
	if string(original) != string(env) {
		t.Fatal("Evaluate modified the attestation bytes")
	}
}

func TestParsePolicyRejectsUnknownFieldWithPosition(t *testing.T) {
	doc := "version: \"1\"\nattestations:\n  - predicateType: vuln\n    bogus: true\n"
	_, err := ParsePolicy([]byte(doc), "policy.yaml")
	if err == nil {
		t.Fatal("expected an error for an unknown field")
	}
	var perr *PolicyParseError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *PolicyParseError, got %T", err)
	}
	if perr.Position == "" {
		t.Errorf("expected a position in %q", err)
	}
	if !strings.Contains(err.Error(), "policy.yaml") {
		t.Errorf("error should name the policy file: %v", err)
	}
}

func TestParsePolicyRejectsBadRegexAndVersion(t *testing.T) {
	for name, doc := range map[string]string{
		"bad-regex": `
version: "1"
attestations:
  - predicateType: vuln
    fields:
      - path: scanner.uri
        matches: "(["
`,
		"bad-version": `
version: "2"
attestations:
  - predicateType: vuln
`,
		"no-attestations": `
version: "1"
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePolicy([]byte(doc), "p.yaml"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPolicyFailureMessageNamesMissing(t *testing.T) {
	err := (&PolicyFailure{Missing: []string{"sbom"}}).Error()
	if !strings.Contains(err, "sbom") {
		t.Fatalf("message should name sbom: %s", err)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
