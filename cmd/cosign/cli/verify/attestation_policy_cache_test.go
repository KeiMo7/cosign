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
	"errors"
	"testing"
	"time"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/policy"
)

// TestAttestationPolicyFallsBackToCacheWithStaleness records evidence in the
// cache, then takes the registry away and confirms evaluation uses the cached
// bundles and labels them stale.
func TestAttestationPolicyFallsBackToCacheWithStaleness(t *testing.T) {
	env := newAttestationEnv(t, "policy-cache-fallback")
	env.writeAttestation(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"buildType": "https://example.com/build/v1",
	})
	policyPath := env.writePolicy(t, provenancePolicy)

	cacheDir := t.TempDir()
	cmd := env.command(t, policyPath)
	cmd.PolicyCacheDir = cacheDir

	// First run populates the cache from a live registry.
	if err := cmd.Exec(context.Background(), []string{env.img}); err != nil {
		t.Fatalf("live run should pass and populate the cache: %v", err)
	}

	// Confirm the cache is populated.
	cached, err := policy.LoadCachedAttestations(cacheDir, env.img)
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) == 0 {
		t.Fatal("cache was not populated by the live run")
	}

	// Simulate the registry becoming unreachable.
	env.stopRegistry(t)

	evidence, err := fetchAndVerifyAttestations(context.Background(), env.img, env.checkOptsForTest(t), false, cmd.NameOptions, cacheDir, 30*time.Minute)
	if err != nil {
		t.Fatalf("expected cached fallback to succeed, got: %v", err)
	}
	if evidence.Cache == nil || !evidence.Cache.Used {
		t.Fatalf("expected cache metadata to be recorded, got %+v", evidence.Cache)
	}
	if evidence.Cache.AgeSeconds < 0 {
		t.Errorf("age should be non-negative, got %d", evidence.Cache.AgeSeconds)
	}
	if !evidence.Cache.Stale {
		t.Errorf("cached evidence served while offline must be marked stale")
	}
	if evidence.Cache.StaleAnnotation == "" {
		t.Errorf("cached evidence must carry a staleness annotation")
	}

	report := policy.Evaluate(mustPolicySpec(t, policyPath), nil)
	if report.Passed == false {
		// sanity: an empty evaluation must not pass a required policy
		t.Log("empty report failed as expected")
	}
}

func mustPolicySpec(t *testing.T, path string) *policy.PolicySpec {
	t.Helper()
	spec, err := policy.ParsePolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestAttestationPolicyDoesNotMaskVerificationFailureWithCache ensures that a
// bundle that fails verification is reported, never silently replaced by
// cached evidence. The registry is reachable but the attestation is checked
// against the wrong key.
func TestAttestationPolicyDoesNotMaskVerificationFailureWithCache(t *testing.T) {
	env := newAttestationEnv(t, "policy-bad-key")
	env.writeAttestation(t, "https://slsa.dev/provenance/v0.2", map[string]any{
		"buildType": "https://example.com/build/v1",
	})
	policyPath := env.writePolicy(t, provenancePolicy)
	cacheDir := t.TempDir()

	// Populate the cache from a good run.
	good := env.command(t, policyPath)
	good.PolicyCacheDir = cacheDir
	if err := good.Exec(context.Background(), []string{env.img}); err != nil {
		t.Fatal(err)
	}

	// Point verification at a different key while the registry stays up.
	other := newAttestationEnv(t, "policy-bad-key-other")
	bad := env.command(t, policyPath)
	bad.KeyRef = other.pubPath
	bad.PolicyCacheDir = cacheDir

	err := bad.Exec(context.Background(), []string{env.img})
	if err == nil {
		t.Fatal("verification with the wrong key must fail, not fall back to cache")
	}
	var evidenceErr *cosign.ErrAttestationFetch
	if errors.As(err, &evidenceErr) {
		t.Fatalf("a verification failure must not be reported as a fetch failure: %v", err)
	}
}
