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
	"sort"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/policy"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

// attestationEvidence is the result of retrieving and verifying attestations
// for one image.
type attestationEvidence struct {
	Verified []cosign.VerifiedAttestation
	// Cache is set only when evidence was served from a local cache.
	Cache *policy.CacheInfo
}

// fetchAndVerifyAttestations retrieves bundles, verifies them, and optionally
// caches them. When retrieval fails for an availability reason and a cache is
// configured, it re-verifies the cached bundles and labels the result stale.
//
// "No attestations exist" is a definitive answer and is never replaced by
// cached evidence, so a policy that requires a type still fails correctly.
func fetchAndVerifyAttestations(ctx context.Context, image string, co *cosign.CheckOpts, local bool, nameOpts []name.Option, cacheDir string, maxAge time.Duration) (attestationEvidence, error) {
	bundles, hash, fetchErr := getBundles(ctx, image, co, local, nameOpts)
	if fetchErr == nil {
		// Cache the exact bundles we are about to verify, before verification,
		// so a later offline run can re-verify them independently.
		if cacheDir != "" {
			if cacheErr := policy.CacheAttestations(cacheDir, image, bundles, time.Now()); cacheErr != nil {
				ui.Warnf(ctx, "unable to write attestation cache: %v", cacheErr)
			}
		}
		return verifyBundles(ctx, bundles, hash, co, nil)
	}

	var noAttestations *cosign.ErrNoMatchingAttestations
	var tagNotFound *cosign.ErrImageTagNotFound
	if errors.As(fetchErr, &noAttestations) || errors.As(fetchErr, &tagNotFound) {
		return attestationEvidence{}, fetchErr
	}
	// Only a retrieval failure may be served from cache. Anything else,
	// including a failure to load attestations from a local layout, is
	// returned as-is so a real error is never masked by stale evidence.
	var fetchFailure *cosign.ErrAttestationFetch
	if cacheDir == "" || !errors.As(fetchErr, &fetchFailure) {
		return attestationEvidence{}, fetchErr
	}

	cached, cacheErr := policy.LoadCachedAttestations(cacheDir, image, co.BundleOptions()...)
	if cacheErr != nil {
		return attestationEvidence{}, fmt.Errorf("attestation fetch failed (%v) and cache could not be read: %w", fetchErr, cacheErr)
	}
	if len(cached) == 0 {
		return attestationEvidence{}, fmt.Errorf("attestation fetch failed and no cached attestations are available: %w", fetchErr)
	}

	cachedBundles := make([]*sgbundle.Bundle, 0, len(cached))
	for _, c := range cached {
		cachedBundles = append(cachedBundles, c.Bundle)
	}
	info := newestCacheInfo(cached, time.Now(), maxAge)
	info.Used = true
	// Evidence served while the registry is unavailable is stale by
	// definition, even within the caller's age budget.
	info.Stale = true
	info.StaleAnnotation = fmt.Sprintf("served from local cache fetched %s ago; registry unavailable", time.Duration(info.AgeSeconds)*time.Second)
	ui.Warnf(ctx, "%s", info.StaleAnnotation)

	return verifyBundles(ctx, cachedBundles, hashForCached(cachedBundles), co, info)
}

// getBundles is a thin seam that keeps the live-fetch classification in one
// place.
func getBundles(ctx context.Context, image string, co *cosign.CheckOpts, local bool, nameOpts []name.Option) ([]*sgbundle.Bundle, *v1.Hash, error) {
	if local {
		return cosign.GetLocalBundles(image, co.BundleOptions()...)
	}
	ref, err := name.ParseReference(image, nameOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing reference: %w", err)
	}
	return cosign.GetBundles(ctx, ref, co.RegistryClientOpts, nameOpts...)
}

// verifyBundles applies the same verification used by the non-policy flow.
func verifyBundles(ctx context.Context, bundles []*sgbundle.Bundle, hash *v1.Hash, co *cosign.CheckOpts, cache *policy.CacheInfo) (attestationEvidence, error) {
	verified, _, err := cosign.VerifyAttestationBundles(ctx, bundles, hash, co)
	if err != nil {
		return attestationEvidence{}, err
	}
	return attestationEvidence{Verified: verified, Cache: cache}, nil
}

// hashForCached reconstructs the image digest from cached bundles. Cached
// bundles were selected for this image, so the subject digest recorded in the
// statement is authoritative and is re-checked during verification.
func hashForCached(bundles []*sgbundle.Bundle) *v1.Hash {
	for _, b := range bundles {
		env, err := b.Envelope()
		if err != nil || env == nil {
			continue
		}
		stmt, err := env.Statement()
		if err != nil || stmt == nil || len(stmt.Subject) == 0 {
			continue
		}
		// Iterate deterministically: map order must not change which subject
		// digest is used to verify cached evidence.
		algs := make([]string, 0, len(stmt.Subject[0].Digest))
		for alg := range stmt.Subject[0].Digest {
			algs = append(algs, alg)
		}
		sort.Strings(algs)
		for _, alg := range algs {
			if h, err := v1.NewHash(alg + ":" + stmt.Subject[0].Digest[alg]); err == nil {
				return &h
			}
		}
	}
	return nil
}

func newestCacheInfo(cached []policy.CachedAttestation, now time.Time, maxAge time.Duration) *policy.CacheInfo {
	var newest time.Time
	for _, c := range cached {
		if c.Fetched.After(newest) {
			newest = c.Fetched
		}
	}
	info := &policy.CacheInfo{CachedAt: newest.UTC().Format(time.RFC3339)}
	if !newest.IsZero() {
		info.AgeSeconds = int64(now.Sub(newest).Seconds())
	}
	if maxAge > 0 {
		info.MaxAgeSeconds = int64(maxAge.Seconds())
	}
	return info
}

// evaluateAttestationReport converts verified bundles into policy inputs and
// evaluates the policy. It performs no I/O.
func evaluateAttestationReport(spec *policy.PolicySpec, evidence attestationEvidence) (*policy.Report, error) {
	inputs := make([]policy.AttestationInput, 0, len(evidence.Verified))
	for _, v := range evidence.Verified {
		env, err := policy.EnvelopeForBundle(v.Bundle)
		if err != nil {
			// Isolate bundles that no longer parse instead of aborting; the
			// report records them as per-attestation errors.
			inputs = append(inputs, policy.AttestationInput{})
			continue
		}
		inputs = append(inputs, policy.AttestationInput{Envelope: env.Envelope, Signer: env.Signer, Issuer: env.Issuer})
	}
	report := policy.Evaluate(spec, inputs)
	report.Cache = evidence.Cache
	return report, nil
}

// evaluateAttestationPolicy evaluates the policy and prints the report.
func evaluateAttestationPolicy(ctx context.Context, spec *policy.PolicySpec, evidence attestationEvidence, output string) (*policy.Report, error) {
	report, err := evaluateAttestationReport(spec, evidence)
	if err != nil {
		return nil, err
	}

	switch output {
	case "json":
		b, err := json.Marshal(report)
		if err != nil {
			return nil, fmt.Errorf("marshaling attestation policy report: %w", err)
		}
		fmt.Println(string(b))
	default:
		ui.Infof(ctx, "%s", report.Summary())
	}

	if !report.Passed {
		return report, &policy.PolicyFailure{Missing: report.MissingRules, Unmet: report.UnmetRules}
	}
	return report, nil
}
