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

// This file turns verified sigstore bundles into the digest-addressed inputs
// consumed by pkg/policy, and provides an on-disk cache of the raw bundle
// payloads so that policy evaluation can degrade to cached evidence when the
// registry is unreachable. Bundles are stored exactly as fetched; nothing here
// rewrites attestation bytes.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
)

// AttestationEnvelope is a verified DSSE envelope together with the identity
// that signed it. The envelope bytes are the exact JSON envelope that was
// covered by the bundle signature.
type AttestationEnvelope struct {
	Envelope []byte
	Signer   string
	Issuer   string
}

// EnvelopeForBundle extracts the raw DSSE envelope from a bundle and, when
// available, the signer identity asserted by the bundle's certificate.
func EnvelopeForBundle(bundle *sgbundle.Bundle) (AttestationEnvelope, error) {
	dsse, ok := bundle.Content.(*protobundle.Bundle_DsseEnvelope)
	if !ok || dsse.DsseEnvelope == nil {
		return AttestationEnvelope{}, errors.New("bundle does not contain a DSSE envelope")
	}
	payload, err := json.Marshal(dsse.DsseEnvelope)
	if err != nil {
		return AttestationEnvelope{}, fmt.Errorf("marshaling DSSE envelope: %w", err)
	}
	out := AttestationEnvelope{Envelope: payload}
	out.Signer, out.Issuer = bundleSignerIdentity(bundle)
	return out, nil
}

// bundleSignerIdentity returns the leaf certificate SAN and OIDC issuer if the
// bundle carries a certificate. Key-signed bundles have no identity and
// return empty strings.
func bundleSignerIdentity(bundle *sgbundle.Bundle) (signer, issuer string) {
	if bundle.VerificationMaterial == nil {
		return "", ""
	}
	var raw []byte
	switch content := bundle.VerificationMaterial.Content.(type) {
	case *protobundle.VerificationMaterial_Certificate:
		if content.Certificate != nil {
			raw = content.Certificate.RawBytes
		}
	case *protobundle.VerificationMaterial_X509CertificateChain:
		if chain := content.X509CertificateChain; chain != nil && len(chain.Certificates) > 0 {
			raw = chain.Certificates[0].RawBytes
		}
	default:
		return "", ""
	}
	if len(raw) == 0 {
		return "", ""
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return "", ""
	}
	signer = signerFromCert(cert)
	issuer = certIssuer(cert)
	return signer, issuer
}

// signerFromCert extracts the Fulcio subject identity, preferring SANs.
func signerFromCert(cert *x509.Certificate) string {
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	for _, name := range cert.Subject.Names {
		if s, ok := name.Value.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// certIssuer reads the Fulcio OIDC issuer extension. It intentionally does not
// depend on pkg/cosign (which imports pkg/policy) to avoid an import cycle.
func certIssuer(cert *x509.Certificate) string {
	const oidcIssuerOID = "1.3.6.1.4.1.57264.1.1"
	for _, ext := range cert.Extensions {
		if ext.Id.String() == oidcIssuerOID {
			return string(ext.Value)
		}
	}
	return ""
}

// CachedAttestation is one bundle persisted by CacheAttestations.
type CachedAttestation struct {
	Bundle  *sgbundle.Bundle
	Fetched time.Time
}

// cacheRecord is the on-disk representation. It is deliberately plain JSON so
// it can be inspected and audited without cosign.
type cacheRecord struct {
	Version   string          `json:"version"`
	Subject   string          `json:"subject"`
	Predicate string          `json:"predicateType,omitempty"`
	FetchedAt time.Time       `json:"fetchedAt"`
	Bundle    json.RawMessage `json:"bundle"`
}

const attestationCacheVersion = "1"

// attestationCacheDir returns the directory used for cached attestations.
func attestationCacheDir(base, subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return filepath.Join(base, hex.EncodeToString(sum[:]))
}

// CacheAttestations stores a copy of each bundle in dir, keyed by the image
// subject. Existing entries are overwritten atomically. The stored bytes are
// the bundle's own JSON encoding, so a cache round-trip is byte-for-byte
// lossless for the payload we later evaluate.
func CacheAttestations(dir, subject string, bundles []*sgbundle.Bundle, now time.Time) error {
	if len(bundles) == 0 {
		return nil
	}
	target := attestationCacheDir(dir, subject)
	if err := os.MkdirAll(target, 0o700); err != nil {
		return err
	}
	for i, b := range bundles {
		raw, err := b.MarshalJSON()
		if err != nil {
			return err
		}
		predicate := ""
		if env, err := b.Envelope(); err == nil && env != nil {
			if stmt, err := env.Statement(); err == nil && stmt != nil {
				predicate = stmt.PredicateType
			}
		}
		rec := cacheRecord{
			Version:   attestationCacheVersion,
			Subject:   subject,
			Predicate: predicate,
			FetchedAt: now.UTC(),
			Bundle:    raw,
		}
		data, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		path := filepath.Join(target, fmt.Sprintf("%02d.json", i))
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}

// LoadCachedAttestations reads bundles cached for the given subject. The
// fetchedAt timestamp of the newest record is returned so callers can label
// the evidence as aged.
func LoadCachedAttestations(dir, subject string, opts ...sgbundle.Option) ([]CachedAttestation, error) {
	target := attestationCacheDir(dir, subject)
	entries, err := os.ReadDir(target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []CachedAttestation
	var skipped []error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, fetched, err := loadCacheEntry(filepath.Join(target, entry.Name()), opts...)
		if err != nil {
			// Isolate a corrupt entry so the remaining cached evidence can
			// still be evaluated.
			skipped = append(skipped, err)
			continue
		}
		out = append(out, CachedAttestation{Bundle: b, Fetched: fetched})
	}
	if len(out) == 0 && len(skipped) > 0 {
		return nil, fmt.Errorf("no usable cached attestations: %w", errors.Join(skipped...))
	}
	return out, nil
}

func loadCacheEntry(path string, opts ...sgbundle.Option) (*sgbundle.Bundle, time.Time, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from the cache directory
	if err != nil {
		return nil, time.Time{}, err
	}
	var rec cacheRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, time.Time{}, fmt.Errorf("reading cached attestation %s: %w", filepath.Base(path), err)
	}
	if rec.Version != attestationCacheVersion {
		return nil, time.Time{}, fmt.Errorf("cached attestation %s has unsupported version %q", filepath.Base(path), rec.Version)
	}
	pb := &protobundle.Bundle{}
	if err := protojson.Unmarshal(rec.Bundle, pb); err != nil {
		return nil, time.Time{}, fmt.Errorf("decoding cached bundle %s: %w", filepath.Base(path), err)
	}
	b, err := sgbundle.NewBundle(pb, opts...)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("validating cached bundle %s: %w", filepath.Base(path), err)
	}
	return b, rec.FetchedAt, nil
}
