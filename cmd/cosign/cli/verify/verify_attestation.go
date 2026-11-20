//
// Copyright 2021 The Sigstore Authors.
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
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/cue"
	"github.com/sigstore/cosign/v3/pkg/cosign/rego"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/policy"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

// VerifyAttestationCommand verifies a signature on a supplied container image
// nolint
type VerifyAttestationCommand struct {
	options.RegistryOptions
	options.CertVerifyOptions
	options.CommonVerifyOptions
	CheckClaims                  bool
	KeyRef                       string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	IgnoreSCT                    bool
	Sk                           bool
	Slot                         string
	Output                       string
	PredicateType                string
	Policies                     []string
	// AttestationPolicy is the path to a declarative attestation policy. When
	// set, attestations are filtered and validated by type before any CUE/Rego
	// policy runs, and a per-attestation report is produced.
	AttestationPolicy string
	// PolicyCacheDir, if set, is used to cache fetched attestations and to fall
	// back to cached evidence when the registry is unreachable.
	PolicyCacheDir      string
	LocalImage          bool
	NameOptions         []name.Option
	Offline             bool
	IgnoreTlog          bool
	MaxWorkers          int
	UseSignedTimestamps bool
}

// Exec runs the verification command
func (c *VerifyAttestationCommand) Exec(ctx context.Context, images []string) (err error) {
	if len(images) == 0 {
		return flag.ErrHelp
	}

	// key and cert identity are mutually exclusive
	if options.NOf(c.KeyRef, c.CertIdentity, c.CertIdentityRegexp) > 1 {
		return &options.KeyAndIdentityParseError{}
	}

	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	var identities []cosign.Identity
	if c.KeyRef == "" && !c.Sk {
		identities, err = c.Identities()
		if err != nil {
			return err
		}
	}

	ociremoteOpts, err := c.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}
	if c.AllowHTTPRegistry || c.AllowInsecure {
		c.NameOptions = append(c.NameOptions, name.Insecure)
	}
	if c.AllowCertificateChain {
		ociremoteOpts = append(ociremoteOpts, ociremote.WithBundleOptions(sgbundle.AllowCertificateChain()))
	}

	co := &cosign.CheckOpts{
		RegistryClientOpts:           ociremoteOpts,
		CertGithubWorkflowTrigger:    c.CertGithubWorkflowTrigger,
		CertGithubWorkflowSha:        c.CertGithubWorkflowSha,
		CertGithubWorkflowName:       c.CertGithubWorkflowName,
		CertGithubWorkflowRepository: c.CertGithubWorkflowRepository,
		CertGithubWorkflowRef:        c.CertGithubWorkflowRef,
		IgnoreSCT:                    c.IgnoreSCT,
		Identities:                   identities,
		Offline:                      c.Offline,
		IgnoreTlog:                   c.IgnoreTlog,
		MaxWorkers:                   c.MaxWorkers,
		UseSignedTimestamps:          c.UseSignedTimestamps,
		AllowCertificateChain:        c.AllowCertificateChain,
		NewBundleFormat:              true,
	}
	vOfflineKey := verifyOfflineWithKey(c.KeyRef, c.Sk, co)

	if c.CheckClaims {
		co.ClaimVerifier = cosign.IntotoSubjectClaimVerifier
	}

	err = SetTrustedMaterial(c.TrustedRootPath, vOfflineKey, co)
	if err != nil {
		return fmt.Errorf("setting trusted material: %w", err)
	}

	// User provides a key. Otherwise, verification requires a Fulcio certificate
	// provided in an attached bundle or OCI annotation.
	var closeSV func()
	co.SigVerifier, closeSV, err = LoadVerifierFromKey(ctx, c.KeyRef, c.Slot, c.Sk)
	if err != nil {
		return fmt.Errorf("loading verifier from key opts: %w", err)
	}
	defer closeSV()

	// NB: There are only 2 kinds of verification right now:
	// 1. You gave us the public key explicitly to verify against so co.SigVerifier is non-nil or,
	// 2. We're going to find an x509 certificate on the signature and verify against Fulcio root trust
	// TODO(nsmith5): Refactor this verification logic to pass back _how_ verification
	// was performed so we don't need to use this fragile logic here.
	fulcioVerified := (co.SigVerifier == nil)

	// A declarative policy is parsed before any image is touched so a broken
	// document is rejected instead of silently allowing verification.
	var spec *policy.PolicySpec
	if c.AttestationPolicy != "" {
		spec, err = policy.ParsePolicyFile(c.AttestationPolicy)
		if err != nil {
			return err
		}
	}

	for _, imageRef := range images {
		var verified []oci.Signature
		var bundleVerified bool
		var report *policy.Report

		if spec != nil {
			selected, bv, r, err := c.verifyWithPolicy(ctx, imageRef, co, spec)
			if err != nil {
				return err
			}
			verified, bundleVerified, report = selected, bv, r
		} else {
			if c.LocalImage {
				verified, bundleVerified, err = cosign.VerifyLocalImageAttestations(ctx, imageRef, co)
				if err != nil {
					return err
				}
			} else {
				ref, err := name.ParseReference(imageRef, c.NameOptions...)
				if err != nil {
					return err
				}

				verified, bundleVerified, err = cosign.VerifyImageAttestations(ctx, ref, co, c.NameOptions...)
				if err != nil {
					return err
				}
			}
		}

		var cuePolicies, regoPolicies []string

		for _, policy := range c.Policies {
			switch filepath.Ext(policy) {
			case ".rego":
				regoPolicies = append(regoPolicies, policy)
			case ".cue":
				cuePolicies = append(cuePolicies, policy)
			default:
				return errors.New("invalid policy format, expected .cue or .rego")
			}
		}

		var checked []oci.Signature
		// When a declarative policy is in effect, it is the sole judge of which
		// attestations are relevant, so the legacy predicate-type check below
		// is skipped. CUE/Rego policies, if also given, still run afterwards
		// against each attestation selected by the declarative policy.
		if spec == nil {
			var validationErrors []error
			// To aid in determining if there's a mismatch in what predicateType
			// we're looking for and what we checked, keep track of them here so
			// that we can help the user figure out if there's a typo, etc.
			checkedPredicateTypes := []string{}
			for _, vp := range verified {
				payload, gotPredicateType, err := policy.AttestationToPayloadJSON(ctx, c.PredicateType, vp)
				if err != nil {
					return fmt.Errorf("converting to consumable policy validation: %w", err)
				}
				checkedPredicateTypes = append(checkedPredicateTypes, gotPredicateType)
				if len(payload) == 0 {
					// This is not the predicate type we're looking for.
					continue
				}

				if len(cuePolicies) > 0 {
					ui.Infof(ctx, "will be validating against CUE policies: %v", cuePolicies)
					cueValidationErr := cue.ValidateJSON(payload, cuePolicies)
					if cueValidationErr != nil {
						validationErrors = append(validationErrors, cueValidationErr)
						continue
					}
				}

				if len(regoPolicies) > 0 {
					ui.Infof(ctx, "will be validating against Rego policies: %v", regoPolicies)
					regoValidationErrs := rego.ValidateJSON(payload, regoPolicies)
					if len(regoValidationErrs) > 0 {
						validationErrors = append(validationErrors, regoValidationErrs...)
						continue
					}
				}

				checked = append(checked, vp)
			}

			if len(validationErrors) > 0 {
				ui.Infof(ctx, "There are %d number of errors occurred during the validation:\n", len(validationErrors))
				for _, v := range validationErrors {
					ui.Infof(ctx, "- %v", v)
				}
				return fmt.Errorf("%d validation errors occurred", len(validationErrors))
			}

			if len(checked) == 0 {
				return fmt.Errorf("none of the attestations matched the predicate type: %s, found: %s", c.PredicateType, strings.Join(checkedPredicateTypes, ","))
			}
		} else {
			// The declarative policy decides which attestations are relevant.
			// Any additional CUE/Rego policies then apply to exactly that set,
			// mirroring the non-policy flow where they apply to the
			// predicate-type-selected set.
			checked = selectedByReport(report, verified)
			if len(checked) == 0 {
				return errors.New("no attestation satisfied the attestation policy")
			}
			if len(cuePolicies) > 0 || len(regoPolicies) > 0 {
				var policyErrors []error
				for _, vp := range checked {
					payload, _, err := policy.AttestationToPayloadJSON(ctx, c.PredicateType, vp)
					if err != nil {
						// The attestation may use one of the policy's other
						// declared types; only the legacy predicate is
						// converted here.
						continue
					}
					if len(payload) == 0 {
						continue
					}
					if len(cuePolicies) > 0 {
						if err := cue.ValidateJSON(payload, cuePolicies); err != nil {
							policyErrors = append(policyErrors, err)
						}
					}
					if len(regoPolicies) > 0 {
						policyErrors = append(policyErrors, rego.ValidateJSON(payload, regoPolicies)...)
					}
				}
				if len(policyErrors) > 0 {
					return fmt.Errorf("CUE/Rego policy validation failed: %w", errors.Join(policyErrors...))
				}
			}
		}

		// TODO: add CUE validation report to `PrintVerificationHeader`.
		PrintVerificationHeader(ctx, imageRef, co, bundleVerified, fulcioVerified)
		if spec != nil {
			// The declarative report was already printed in verifyWithPolicy.
			// Name the evidence used so a cached run is never mistaken for a
			// live one.
			if report != nil && report.Cache != nil && report.Cache.Used {
				ui.Infof(ctx, "Attestations were evaluated from a local cache (stale=%t).", report.Cache.Stale)
			}
		}
		// The attestations are always JSON, so use the raw "text" mode for outputting them instead of conversion.
		// With a declarative policy, only attestations that satisfied a rule are printed.
		PrintVerification(ctx, checked, "text")
	}

	return nil
}

// verifyWithPolicy fetches and verifies attestations, applies the declarative
// policy, prints the report and returns the verified attestations together
// with the report. It is only called when --attestation-policy is set.
func (c *VerifyAttestationCommand) verifyWithPolicy(ctx context.Context, imageRef string, co *cosign.CheckOpts, spec *policy.PolicySpec) ([]oci.Signature, bool, *policy.Report, error) {
	evidence, err := fetchAndVerifyAttestations(ctx, imageRef, co, c.LocalImage, c.NameOptions, c.PolicyCacheDir, 0)
	if err != nil {
		// An image that simply has no attestations is not a fetch failure: the
		// policy decides whether that is acceptable, and if not, names the
		// missing types. Any other error (image missing, registry unavailable,
		// verification failed) is returned as-is.
		var noAttestations *cosign.ErrNoMatchingAttestations
		if !errors.As(err, &noAttestations) {
			return nil, false, nil, err
		}
	}

	all := make([]oci.Signature, 0, len(evidence.Verified))
	for _, v := range evidence.Verified {
		all = append(all, v.Signature)
	}

	report, err := evaluateAttestationPolicy(ctx, spec, evidence, c.Output)
	if err != nil {
		// Return the verified set so callers can still report how far they got.
		return all, false, report, err
	}
	return all, true, report, nil
}

// selectedByReport returns the verified attestations that the policy selected
// and that satisfied at least one rule. Ordering follows the verified set so
// output stays stable.
func selectedByReport(report *policy.Report, verified []oci.Signature) []oci.Signature {
	if report == nil {
		return verified
	}
	wanted := make(map[string]struct{}, len(report.Results))
	for _, r := range report.Results {
		if r.Selected && len(r.MatchedRules) > 0 {
			wanted[r.Digest] = struct{}{}
		}
	}
	out := make([]oci.Signature, 0, len(wanted))
	for _, sig := range verified {
		payload, err := sig.Payload()
		if err != nil {
			continue
		}
		if _, ok := wanted[policy.EnvelopeDigest(payload)]; ok {
			out = append(out, sig)
		}
	}
	return out
}
