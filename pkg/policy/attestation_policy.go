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

// This file implements the declarative attestation policy used by
// `cosign verify-attestation --attestation-policy`.
//
// A policy document declares one or more attestation types and, optionally,
// the fields that the predicate of a matching attestation must contain. The
// same PolicySpec value drives both the type filter and the content check, so
// an attestation can never be selected by one rule and validated against a
// different one.
//
// Evaluation is pure: attestation bytes are only read, never rewritten, and
// the report is built from deterministic, digest-addressed entries. Reports
// deliberately avoid echoing predicate values so that they are safe to attach
// to build logs; field differences are described by path, expected value, and
// a hash of the observed value.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"gopkg.in/yaml.v3"
)

const (
	// PolicyVersion is the only attestation policy document version understood
	// by this implementation.
	PolicyVersion = "1"

	// ReportVersion is the version of the evaluation report format.
	ReportVersion = "1"
)

// PolicySpec is a parsed, validated attestation policy document.
type PolicySpec struct {
	Version      string
	Attestations []AttestationRule
	// source records where the policy was loaded from, for error messages.
	source string
}

// AttestationRule declares a required (or optional) attestation type and the
// fields its predicate must contain.
type AttestationRule struct {
	// Name identifies the rule in reports. It defaults to PredicateType.
	Name string
	// PredicateType is the type as written in the policy document (a short
	// name from --type, or a full URI).
	PredicateType string
	// PredicateURI is the resolved full URI used for matching and validation.
	PredicateURI string
	// Required rules must be satisfied for the policy to pass.
	Required bool
	// MinCount is the minimum number of attestations that must satisfy the
	// rule. It defaults to 1.
	MinCount int
	// Fields are assertions on the predicate of matching attestations.
	Fields []FieldRule
}

// FieldRule is a single assertion on a predicate field.
type FieldRule struct {
	// Path addresses a field inside the predicate. Dot notation with optional
	// [n] array indices or RFC 6901 JSON Pointer notation (leading "/") are
	// accepted.
	Path string
	// Present asserts the presence of the field. It defaults to true. When
	// explicitly false, the field must be absent.
	Present bool
	// Equals asserts deep equality with the given value.
	Equals any
	// Matches asserts that the field is a string matching the regular
	// expression.
	Matches string
	// NonEmpty asserts that the value is not empty.
	NonEmpty bool
	// hasEquals distinguishes `equals:` from an omitted value.
	hasEquals bool
	// matchesRe is the compiled form of Matches.
	matchesRe *regexp.Regexp
}

// PolicyParseError describes a policy document that could not be accepted.
// The Position is "line:column" when known so operators can fix the document
// without guessing.
type PolicyParseError struct {
	Source   string
	Position string
	Err      error
}

func (e *PolicyParseError) Error() string {
	loc := e.Source
	if loc == "" {
		loc = "<policy>"
	}
	if e.Position != "" {
		loc += ":" + e.Position
	}
	return fmt.Sprintf("invalid attestation policy %s: %v", loc, e.Err)
}

func (e *PolicyParseError) Unwrap() error { return e.Err }

// EnvelopeDigest returns the SHA-256 of the raw DSSE envelope in
// "sha256:<hex>" form, matching the digest recorded in report entries.
func EnvelopeDigest(envelope []byte) string {
	sum := sha256.Sum256(envelope)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// AttestationInput is one verified attestation presented for evaluation.
type AttestationInput struct {
	// Envelope is the raw DSSE envelope. It is only read, never modified.
	Envelope []byte
	// Signer is the identity that produced the attestation, if known.
	Signer string
	// Issuer is the OIDC issuer of the signer, if known.
	Issuer string
}

// FieldDiff describes a single field-level difference. It never contains the
// observed value; ActualSHA256 allows correlation without disclosing content.
type FieldDiff struct {
	Path         string `json:"path"`
	Reason       string `json:"reason"` // missing, unexpected_present, mismatch, invalid_type, empty
	Expected     any    `json:"expected,omitempty"`
	ActualType   string `json:"actualType,omitempty"`
	ActualSHA256 string `json:"actualSHA256,omitempty"`
}

// AttestationResult is the outcome of inspecting one attestation.
type AttestationResult struct {
	// Digest is the SHA-256 of the raw DSSE envelope, in "sha256:<hex>" form.
	Digest string `json:"digest"`
	// PredicateType is the type declared by the attestation.
	PredicateType string `json:"predicateType,omitempty"`
	// Selected reports whether any rule in the policy declared this type.
	Selected bool `json:"selected"`
	// Signer is the identity that signed the attestation, if known.
	Signer string `json:"signer,omitempty"`
	// Issuer is the OIDC issuer of the signer, if known.
	Issuer string `json:"issuer,omitempty"`
	// MatchedRules lists the rules this attestation fully satisfied.
	MatchedRules []string `json:"matchedRules,omitempty"`
	// Diffs lists field-level differences per rule.
	Diffs []RuleDiff `json:"diffs,omitempty"`
	// Error isolates a per-attestation parsing failure. Other attestations
	// continue to be evaluated.
	Error string `json:"error,omitempty"`
}

// RuleDiff groups the field differences observed for one rule.
type RuleDiff struct {
	Rule   string      `json:"rule"`
	Reason string      `json:"reason,omitempty"`
	Fields []FieldDiff `json:"fields,omitempty"`
}

// RuleResult is the aggregate outcome for one declared rule.
type RuleResult struct {
	Name          string `json:"name"`
	PredicateType string `json:"predicateType"`
	PredicateURI  string `json:"predicateURI"`
	Required      bool   `json:"required"`
	MinCount      int    `json:"minCount"`
	// Present is the number of attestations that declared this type.
	Present int `json:"present"`
	// Matched is the number of attestations that fully satisfied the rule.
	Matched int `json:"matched"`
	// Missing is true when the type itself was absent.
	Missing bool `json:"missing"`
	// Satisfied reports whether Matched >= MinCount.
	Satisfied bool `json:"satisfied"`
}

// SignerResult shows, for one signing identity, which rules it satisfied.
type SignerResult struct {
	Signer             string   `json:"signer"`
	Issuer             string   `json:"issuer,omitempty"`
	SatisfiedRules     []string `json:"satisfiedRules"`
	UnsatisfiedRules   []string `json:"unsatisfiedRules"`
	AttestationDigests []string `json:"attestationDigests"`
}

// CacheInfo records that a report was produced from a local cache.
type CacheInfo struct {
	Used            bool   `json:"used"`
	CachedAt        string `json:"cachedAt,omitempty"`
	AgeSeconds      int64  `json:"ageSeconds,omitempty"`
	Stale           bool   `json:"stale"`
	MaxAgeSeconds   int64  `json:"maxAgeSeconds,omitempty"`
	StaleAnnotation string `json:"staleAnnotation,omitempty"`
}

// Report is the complete, machine-readable outcome of an evaluation.
type Report struct {
	Version  string              `json:"version"`
	Passed   bool                `json:"passed"`
	Rules    []RuleResult        `json:"rules"`
	Results  []AttestationResult `json:"results"`
	BySigner []SignerResult      `json:"bySigner"`
	// MissingRules names required types that were absent entirely.
	MissingRules []string `json:"missingRules,omitempty"`
	// UnmetRules names all required rules that were not satisfied, whether the
	// type was missing or its content did not meet the declared fields.
	UnmetRules []string `json:"unmetRules,omitempty"`
	// IsolatedErrors is the number of attestations that could not be parsed.
	IsolatedErrors int `json:"isolatedErrors"`
	// Skipped is the number of attestations not selected by any rule.
	Skipped int        `json:"skipped"`
	Cache   *CacheInfo `json:"cache,omitempty"`
}

// PolicyFailure is returned by the CLI when a policy does not pass. Its
// message names rules and types only; it never includes image references or
// attestation content.
type PolicyFailure struct {
	Missing []string
	Unmet   []string
}

func (e *PolicyFailure) Error() string {
	var parts []string
	if len(e.Missing) > 0 {
		parts = append(parts, fmt.Sprintf("missing required attestations: %s", strings.Join(e.Missing, ", ")))
	}
	if len(e.Unmet) > 0 {
		parts = append(parts, fmt.Sprintf("unsatisfied attestation rules: %s", strings.Join(e.Unmet, ", ")))
	}
	if len(parts) == 0 {
		return "attestation policy did not pass"
	}
	return "attestation policy did not pass: " + strings.Join(parts, "; ")
}

// ParsePolicy parses and validates a policy document. JSON is accepted too
// because it is a subset of YAML.
func ParsePolicy(data []byte, source string) (*PolicySpec, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, &PolicyParseError{Source: source, Err: err}
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return nil, &PolicyParseError{Source: source, Err: errors.New("empty document")}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, parseErrAt(source, root, "expected a mapping at the document root")
	}

	type rawField struct {
		Path     string `yaml:"path"`
		Present  *bool  `yaml:"present"`
		Equals   any    `yaml:"equals"`
		Matches  string `yaml:"matches"`
		NonEmpty bool   `yaml:"nonEmpty"`
	}
	type rawRule struct {
		Name          string     `yaml:"name"`
		PredicateType string     `yaml:"predicateType"`
		Required      *bool      `yaml:"required"`
		MinCount      *int       `yaml:"minCount"`
		Fields        []rawField `yaml:"fields"`
	}
	type rawDoc struct {
		Version      string    `yaml:"version"`
		Attestations []rawRule `yaml:"attestations"`
	}

	var raw rawDoc
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, parseDecodeError(source, err)
	}

	spec := &PolicySpec{Version: raw.Version, source: source}
	if spec.Version == "" {
		spec.Version = PolicyVersion
	}
	if spec.Version != PolicyVersion {
		return nil, &PolicyParseError{Source: source, Err: fmt.Errorf("unsupported version %q (want %q)", spec.Version, PolicyVersion)}
	}
	if len(raw.Attestations) == 0 {
		return nil, &PolicyParseError{Source: source, Err: errors.New("no attestations declared")}
	}

	ruleNodes := childSeq(root, "attestations")
	names := map[string]struct{}{}
	for i, rr := range raw.Attestations {
		node := nodeAt(ruleNodes, i)
		if rr.PredicateType == "" {
			return nil, parseErrAt(source, node, "attestation rule %d is missing predicateType", i)
		}
		uri, err := options.ParsePredicateType(rr.PredicateType)
		if err != nil {
			return nil, parseErrAt(source, node, "attestation rule %d: %v", i, err)
		}
		name := rr.Name
		if name == "" {
			name = rr.PredicateType
		}
		if _, dup := names[name]; dup {
			return nil, parseErrAt(source, node, "duplicate attestation rule name %q", name)
		}
		names[name] = struct{}{}

		rule := AttestationRule{
			Name:          name,
			PredicateType: rr.PredicateType,
			PredicateURI:  uri,
			Required:      true,
			MinCount:      1,
		}
		if rr.Required != nil {
			rule.Required = *rr.Required
		}
		if rr.MinCount != nil {
			if *rr.MinCount < 1 {
				return nil, parseErrAt(source, node, "rule %q: minCount must be at least 1", name)
			}
			rule.MinCount = *rr.MinCount
		}

		fieldNodes := childSeq(node, "fields")
		for j, rf := range rr.Fields {
			fnode := nodeAt(fieldNodes, j)
			if rf.Path == "" {
				return nil, parseErrAt(source, fnode, "rule %q: field %d is missing path", name, j)
			}
			field := FieldRule{
				Path:     rf.Path,
				Present:  true,
				Equals:   rf.Equals,
				Matches:  rf.Matches,
				NonEmpty: rf.NonEmpty,
			}
			if rf.Present != nil {
				field.Present = *rf.Present
			}
			hasEquals := childValue(fnode, "equals") != nil
			field.hasEquals = hasEquals
			if rf.Matches != "" {
				re, err := regexp.Compile(rf.Matches)
				if err != nil {
					return nil, parseErrAt(source, fnode, "rule %q: invalid matches expression: %v", name, err)
				}
				field.matchesRe = re
			}
			if !field.Present && (hasEquals || field.Matches != "" || field.NonEmpty) {
				return nil, parseErrAt(source, fnode, "rule %q: field %q sets present: false together with a value assertion", name, field.Path)
			}
			// A field with only "present" (the default) is still a useful
			// assertion: the field must exist.
			rule.Fields = append(rule.Fields, field)
		}
		spec.Attestations = append(spec.Attestations, rule)
	}
	return spec, nil
}

// ParsePolicyFile reads and parses a policy document from disk.
func ParsePolicyFile(path string) (*PolicySpec, error) {
	b, err := os.ReadFile(path) //nolint:gosec // path is user-supplied by design
	if err != nil {
		return nil, &PolicyParseError{Source: path, Err: err}
	}
	return ParsePolicy(b, path)
}

func parseErrAt(source string, node *yaml.Node, format string, args ...any) error {
	pos := ""
	if node != nil && node.Line > 0 {
		pos = strconv.Itoa(node.Line) + ":" + strconv.Itoa(node.Column)
	}
	return &PolicyParseError{Source: source, Position: pos, Err: fmt.Errorf(format, args...)}
}

// parseDecodeError extracts the first line number from a yaml decoding error,
// which is what yaml.v3 reports for unknown fields and type mismatches, and
// records it as the error position.
func parseDecodeError(source string, err error) error {
	pos := ""
	msg := err.Error()
	if i := strings.Index(msg, "line "); i >= 0 {
		rest := msg[i+len("line "):]
		for _, r := range rest {
			if r < '0' || r > '9' {
				break
			}
			pos += string(r)
		}
	}
	return &PolicyParseError{Source: source, Position: pos, Err: err}
}

func childValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func childSeq(m *yaml.Node, key string) []*yaml.Node {
	n := childValue(m, key)
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

func nodeAt(nodes []*yaml.Node, i int) *yaml.Node {
	if i >= 0 && i < len(nodes) {
		return nodes[i]
	}
	return nil
}

// Evaluate applies the policy to the given attestations. It never fails
// because of an individual attestation: malformed inputs are isolated in the
// report and the remaining attestations are still evaluated.
func Evaluate(spec *PolicySpec, inputs []AttestationInput) *Report {
	report := &Report{Version: ReportVersion, Rules: ruleResults(spec)}

	signers := map[string]*signerAggregate{}
	var signerOrder []string

	for _, in := range inputs {
		sum := sha256.Sum256(in.Envelope)
		res := AttestationResult{
			Digest: "sha256:" + hex.EncodeToString(sum[:]),
			Signer: in.Signer,
			Issuer: in.Issuer,
		}

		parsed, err := parseEnvelope(in.Envelope)
		if err != nil {
			res.Error = err.Error()
			report.IsolatedErrors++
			report.Results = append(report.Results, res)
			continue
		}
		res.PredicateType = parsed.predicateType
		empty := predicateEmpty(parsed)

		for i := range spec.Attestations {
			rule := &spec.Attestations[i]
			// Selection and content validation both use the same rule object,
			// so an attestation is validated only against the rule that
			// declares its type.
			if parsed.predicateType != rule.PredicateURI {
				continue
			}
			res.Selected = true
			report.Rules[i].Present++

			if empty {
				// A declared type with an empty predicate is a failure, not a
				// missing attestation.
				res.Diffs = append(res.Diffs, RuleDiff{Rule: rule.Name, Reason: "empty_predicate"})
				continue
			}
			if diffs := validateFields(parsed.predicate, rule.Fields); len(diffs) > 0 {
				res.Diffs = append(res.Diffs, RuleDiff{Rule: rule.Name, Reason: "field_mismatch", Fields: diffs})
				continue
			}
			res.MatchedRules = append(res.MatchedRules, rule.Name)
			report.Rules[i].Matched++
		}

		report.Results = append(report.Results, res)
		if !res.Selected {
			report.Skipped++
			continue
		}

		agg := signers[res.Signer]
		if agg == nil {
			agg = &signerAggregate{issuer: res.Issuer, satisfied: map[string]struct{}{}, digests: map[string]struct{}{}}
			signers[res.Signer] = agg
			signerOrder = append(signerOrder, res.Signer)
		}
		agg.digests[res.Digest] = struct{}{}
		for _, name := range res.MatchedRules {
			agg.satisfied[name] = struct{}{}
		}
	}

	for i := range report.Rules {
		r := &report.Rules[i]
		r.Satisfied = r.Matched >= r.MinCount
		r.Missing = r.Present == 0
		if r.Required && !r.Satisfied {
			report.UnmetRules = append(report.UnmetRules, r.Name)
			if r.Missing {
				report.MissingRules = append(report.MissingRules, r.Name)
			}
		}
	}

	report.Passed = len(report.UnmetRules) == 0
	report.BySigner = buildSignerResults(signers, signerOrder, spec)
	report.Results = sortResults(report.Results)
	sort.Strings(report.MissingRules)
	sort.Strings(report.UnmetRules)
	return report
}

func ruleResults(spec *PolicySpec) []RuleResult {
	out := make([]RuleResult, 0, len(spec.Attestations))
	for _, r := range spec.Attestations {
		out = append(out, RuleResult{
			Name:          r.Name,
			PredicateType: r.PredicateType,
			PredicateURI:  r.PredicateURI,
			Required:      r.Required,
			MinCount:      r.MinCount,
		})
	}
	return out
}

// signerAggregate accumulates the rules satisfied by one signing identity.
type signerAggregate struct {
	issuer    string
	satisfied map[string]struct{}
	digests   map[string]struct{}
}

// parsedAttestation is the read-only view of an in-toto statement.
type parsedAttestation struct {
	predicateType string
	predicate     any
	predicateSet  bool
}

func parseEnvelope(envelope []byte) (*parsedAttestation, error) {
	var env struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("decoding DSSE envelope: %w", err)
	}
	if env.Payload == "" {
		return nil, errors.New("DSSE envelope has no payload")
	}
	decoded, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding DSSE payload: %w", err)
	}
	var stmt map[string]any
	if err := json.Unmarshal(decoded, &stmt); err != nil {
		return nil, fmt.Errorf("decoding in-toto statement: %w", err)
	}
	pt, _ := stmt["predicateType"].(string)
	if pt == "" {
		return nil, errors.New("in-toto statement has no predicateType")
	}
	pred, ok := stmt["predicate"]
	return &parsedAttestation{predicateType: pt, predicate: pred, predicateSet: ok}, nil
}

// predicateEmpty reports whether the statement carries no predicate content.
func predicateEmpty(p *parsedAttestation) bool {
	if !p.predicateSet || p.predicate == nil {
		return true
	}
	switch v := p.predicate.(type) {
	case string:
		return strings.TrimSpace(v) == ""
	case map[string]any:
		return len(v) == 0
	case []any:
		return len(v) == 0
	}
	return false
}

func buildSignerResults(signers map[string]*signerAggregate, order []string, spec *PolicySpec) []SignerResult {
	out := make([]SignerResult, 0, len(signers))
	sortedOrder := append([]string(nil), order...)
	sort.Strings(sortedOrder)
	for _, name := range sortedOrder {
		agg := signers[name]
		sr := SignerResult{Signer: name, Issuer: agg.issuer, SatisfiedRules: []string{}, UnsatisfiedRules: []string{}}
		for _, rule := range spec.Attestations {
			if _, ok := agg.satisfied[rule.Name]; ok {
				sr.SatisfiedRules = append(sr.SatisfiedRules, rule.Name)
			} else if rule.Required {
				sr.UnsatisfiedRules = append(sr.UnsatisfiedRules, rule.Name)
			}
		}
		for d := range agg.digests {
			sr.AttestationDigests = append(sr.AttestationDigests, d)
		}
		sort.Strings(sr.AttestationDigests)
		out = append(out, sr)
	}
	return out
}

// sortResults orders attestations deterministically by digest, then signer.
func sortResults(in []AttestationResult) []AttestationResult {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Digest != in[j].Digest {
			return in[i].Digest < in[j].Digest
		}
		return in[i].Signer < in[j].Signer
	})
	for i := range in {
		sort.Strings(in[i].MatchedRules)
		sort.SliceStable(in[i].Diffs, func(a, b int) bool { return in[i].Diffs[a].Rule < in[i].Diffs[b].Rule })
		for j := range in[i].Diffs {
			sort.SliceStable(in[i].Diffs[j].Fields, func(a, b int) bool {
				return in[i].Diffs[j].Fields[a].Path < in[i].Diffs[j].Fields[b].Path
			})
		}
	}
	return in
}

func validateFields(predicate any, fields []FieldRule) []FieldDiff {
	if len(fields) == 0 {
		return nil
	}
	obj, ok := predicate.(map[string]any)
	if !ok {
		return []FieldDiff{{Path: "predicate", Reason: "invalid_type", ActualType: jsonType(predicate)}}
	}
	var diffs []FieldDiff
	for _, f := range fields {
		value, found := lookupPath(obj, f.Path)
		if !f.Present {
			if found {
				diffs = append(diffs, FieldDiff{Path: f.Path, Reason: "unexpected_present", ActualType: jsonType(value)})
			}
			continue
		}
		if !found || value == nil {
			diffs = append(diffs, FieldDiff{Path: f.Path, Reason: "missing"})
			continue
		}
		if f.hasEquals && !jsonEqual(f.Equals, value) {
			diffs = append(diffs, FieldDiff{
				Path:         f.Path,
				Reason:       "mismatch",
				Expected:     f.Equals,
				ActualType:   jsonType(value),
				ActualSHA256: valueDigest(value),
			})
		}
		if f.matchesRe != nil || f.Matches != "" {
			s, isString := value.(string)
			if !isString {
				diffs = append(diffs, FieldDiff{Path: f.Path, Reason: "invalid_type", Expected: f.Matches, ActualType: jsonType(value)})
			} else if f.matchesRe != nil && !f.matchesRe.MatchString(s) {
				diffs = append(diffs, FieldDiff{
					Path:         f.Path,
					Reason:       "mismatch",
					Expected:     f.Matches,
					ActualType:   "string",
					ActualSHA256: valueDigest(value),
				})
			}
		}
		if f.NonEmpty && isEmptyValue(value) {
			diffs = append(diffs, FieldDiff{Path: f.Path, Reason: "empty", ActualType: jsonType(value)})
		}
	}
	return diffs
}

// lookupPath resolves a dot path with optional [n] indices, or a JSON Pointer.
func lookupPath(root map[string]any, path string) (any, bool) {
	if strings.HasPrefix(path, "/") {
		return lookupPointer(root, path)
	}
	var cur any = root
	for _, seg := range strings.Split(path, ".") {
		name, indices, err := splitSegment(seg)
		if err != nil {
			return nil, false
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[name]
		if !ok {
			return nil, false
		}
		for _, idx := range indices {
			arr, ok := cur.([]any)
			if !ok || idx < 0 || idx >= len(arr) {
				return nil, false
			}
			cur = arr[idx]
		}
	}
	return cur, true
}

func splitSegment(seg string) (string, []int, error) {
	open := strings.IndexByte(seg, '[')
	if open < 0 {
		return seg, nil, nil
	}
	name := seg[:open]
	rest := seg[open:]
	var indices []int
	for strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", nil, errors.New("unterminated index")
		}
		n, err := strconv.Atoi(rest[1:end])
		if err != nil {
			return "", nil, err
		}
		indices = append(indices, n)
		rest = rest[end+1:]
	}
	if rest != "" {
		return "", nil, errors.New("trailing characters after index")
	}
	return name, indices, nil
}

func lookupPointer(root map[string]any, path string) (any, bool) {
	var cur any = root
	for _, raw := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[token]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(token)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// jsonEqual compares after normalizing through JSON so that YAML integers and
// JSON floats compare as equal.
func jsonEqual(a, b any) bool {
	na, err := normalizeJSON(a)
	if err != nil {
		return reflect.DeepEqual(a, b)
	}
	nb, err := normalizeJSON(b)
	if err != nil {
		return reflect.DeepEqual(a, b)
	}
	return reflect.DeepEqual(na, nb)
}

func normalizeJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func valueDigest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "bool"
	case json.Number, float64, float32, int, int64, uint64:
		return "number"
	}
	return fmt.Sprintf("%T", v)
}

func isEmptyValue(v any) bool {
	switch val := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(val) == ""
	case map[string]any:
		return len(val) == 0
	case []any:
		return len(val) == 0
	}
	return false
}

// Summary renders a leak-free, human-readable summary. It never includes the
// image reference or predicate values, only rule metadata, counts and digests.
func (r *Report) Summary() string {
	var b strings.Builder
	status := "PASSED"
	if !r.Passed {
		status = "FAILED"
	}
	fmt.Fprintf(&b, "attestation policy: %s\n", status)
	for _, rule := range r.Rules {
		mark := "ok"
		if rule.Required && !rule.Satisfied {
			mark = "FAIL"
		}
		req := "optional"
		if rule.Required {
			req = "required"
		}
		fmt.Fprintf(&b, "  [%s] %s (%s, matched %d/%d, present %d)\n", mark, rule.Name, req, rule.Matched, rule.MinCount, rule.Present)
	}
	for _, res := range r.Results {
		if res.Error != "" {
			fmt.Fprintf(&b, "  isolated error for attestation %s: %s\n", res.Digest, res.Error)
			continue
		}
		for _, rd := range res.Diffs {
			for _, f := range rd.Fields {
				fmt.Fprintf(&b, "  attestation %s rule %s field %s: %s\n", res.Digest, rd.Rule, f.Path, f.Reason)
			}
			if len(rd.Fields) == 0 {
				fmt.Fprintf(&b, "  attestation %s rule %s: %s\n", res.Digest, rd.Rule, rd.Reason)
			}
		}
	}
	fmt.Fprintf(&b, "  %d attestations evaluated, %d skipped by type filter, %d isolated errors\n", len(r.Results), r.Skipped, r.IsolatedErrors)
	if r.Cache != nil && r.Cache.Used {
		fmt.Fprintf(&b, "  evaluated from local cache fetched at %s (%ds old, stale=%t)\n", r.Cache.CachedAt, r.Cache.AgeSeconds, r.Cache.Stale)
	}
	return b.String()
}

// MarshalJSON emits the report with stable formatting.
func (r *Report) MarshalJSON() ([]byte, error) {
	type alias Report
	return json.Marshal((*alias)(r))
}
