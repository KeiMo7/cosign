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
	"os"
	"path/filepath"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

// testBundle builds a minimal, valid v0.3 key-signed attestation bundle.
func testBundle(t *testing.T, predicateType string, predicate any) *sgbundle.Bundle {
	t.Helper()
	env := makeEnvelope(t, predicateType, predicate)
	var decoded struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	}
	if err := json.Unmarshal(env, &decoded); err != nil {
		t.Fatal(err)
	}
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				PayloadType: decoded.PayloadType,
				Payload:     mustBase64(t, decoded.Payload),
				Signatures:  []*protodsse.Signature{{Sig: []byte("not-a-real-signature")}},
			},
		},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: "test"},
			},
		},
	}
	b, err := sgbundle.NewBundle(pb)
	if err != nil {
		t.Fatalf("test bundle invalid: %v", err)
	}
	return b
}

func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCacheRoundTripPreservesEnvelope(t *testing.T) {
	dir := t.TempDir()
	subject := "example.com/repo:tag"
	original := testBundle(t, "https://slsa.dev/provenance/v0.2", map[string]any{"buildType": "x"})
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	if err := CacheAttestations(dir, subject, []*sgbundle.Bundle{original}, now); err != nil {
		t.Fatal(err)
	}
	cached, err := LoadCachedAttestations(dir, subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) != 1 {
		t.Fatalf("got %d cached attestations, want 1", len(cached))
	}
	if !cached[0].Fetched.Equal(now) {
		t.Errorf("Fetched = %v, want %v", cached[0].Fetched, now)
	}

	before, err := original.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	after, err := cached[0].Bundle.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(before, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &b); err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("cached bundle differs from original:\n%s\n%s", ja, jb)
	}
}

func TestCacheIsNamespacedBySubject(t *testing.T) {
	dir := t.TempDir()
	b := testBundle(t, "https://slsa.dev/provenance/v0.2", map[string]any{"a": 1})
	if err := CacheAttestations(dir, "subject-a", []*sgbundle.Bundle{b}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCachedAttestations(dir, "subject-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("cache for a different subject should be empty, got %d", len(got))
	}
	// The subject string itself must not appear in the directory layout.
	var found bool
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && filepath.Base(path) == "subject-a" {
			found = true
		}
		return nil
	})
	if found {
		t.Error("the subject was written into the cache path")
	}
}

func TestCacheRejectsCorruptEntry(t *testing.T) {
	dir := t.TempDir()
	subject := "example.com/repo:tag"
	b := testBundle(t, "https://slsa.dev/provenance/v0.2", map[string]any{"a": 1})
	if err := CacheAttestations(dir, subject, []*sgbundle.Bundle{b}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Corrupt the stored bundle.
	target := attestationCacheDir(dir, subject)
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("nothing cached")
	}
	path := filepath.Join(target, entries[0].Name())
	if err := os.WriteFile(path, []byte(`{"version":"1","bundle":{"bogus":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCachedAttestations(dir, subject); err == nil {
		t.Fatal("expected an error when the only cache entry is corrupt")
	}
}

func TestEnvelopeForBundleExtractsEnvelope(t *testing.T) {
	b := testBundle(t, "https://slsa.dev/provenance/v0.2", map[string]any{"buildType": "x"})
	env, err := EnvelopeForBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseEnvelope(env.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.predicateType != "https://slsa.dev/provenance/v0.2" {
		t.Errorf("predicateType = %q", parsed.predicateType)
	}
}
