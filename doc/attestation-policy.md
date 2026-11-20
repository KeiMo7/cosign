# Declarative attestation policy

`cosign verify-attestation --attestation-policy <FILE>` selects and validates
attestations according to a policy document instead of only checking that an
attestation of the requested type exists.

The same policy drives both the type filter and the content check: an
attestation is only ever validated against the rule that declares its
`predicateType`, so the two cannot diverge. Rules are evaluated for every
attestation, and each attestation gets its own entry in the report.

Without `--attestation-policy`, verification behaves exactly as before.

## Document format

The document is YAML (or JSON, which is a subset of YAML).

```yaml
version: "1"
attestations:
  - name: provenance            # optional, defaults to predicateType
    predicateType: slsaprovenance
    required: true              # default true
    minCount: 1                 # default 1
    fields:
      - path: builder.id        # dot notation, [n] indices, or /json/pointer
        matches: "^https://github.com/"
      - path: buildType
        equals: https://slsa.dev/provenance/v1
      - path: invocation.parameters
        nonEmpty: true
      - path: deprecatedField
        present: false
  - name: sbom
    predicateType: cyclonedx
    fields:
      - path: /specVersion      # RFC 6901 JSON Pointer
        equals: "1.5"
```

`predicateType` accepts the same short names as `--type`
(`slsaprovenance`, `cyclonedx`, `spdx`, `vuln`, `custom`, ...) or a full URI.

Each field supports exactly one of:

| key        | meaning                                                           |
|------------|-------------------------------------------------------------------|
| `present`  | the field must exist (default) or must be absent (`present: false`) |
| `equals`   | deep equality with the given value                                |
| `matches`  | the value is a string matching the regular expression             |
| `nonEmpty` | the value is not an empty string, object or array                 |

A declared `predicateType` whose predicate is empty fails its rule; it is not
treated as a missing attestation.

## Report

`-o json` prints a report that is safe to attach to build logs. It contains no
image references and no predicate values:

```json
{
  "version": "1",
  "passed": false,
  "rules": [
    {"name": "sbom", "predicateType": "cyclonedx", "predicateURI": "https://cyclonedx.org/bom",
     "required": true, "minCount": 1, "present": 1, "matched": 0, "missing": false, "satisfied": false}
  ],
  "results": [
    {"digest": "sha256:...", "predicateType": "https://cyclonedx.org/bom", "selected": true,
     "diffs": [{"rule": "sbom", "reason": "field_mismatch",
                "fields": [{"path": "specVersion", "reason": "mismatch", "expected": "1.5",
                            "actualType": "string", "actualSHA256": "..."}]}]}
  ],
  "bySigner": [{"signer": "builder@example.com", "satisfiedRules": [], "unsatisfiedRules": ["sbom"],
                "attestationDigests": ["sha256:..."]}],
  "missingRules": [],
  "unmetRules": ["sbom"],
  "isolatedErrors": 0,
  "skipped": 0
}
```

Every result is addressed by the SHA-256 of the raw DSSE envelope, so a
decision can be traced to the exact attestation later. Observed values are
reported as `actualSHA256` rather than in cleartext.

## Failure handling

* A policy that cannot be parsed is rejected; the error names the file and,
  where available, the line. Verification is never allowed by default.
* A malformed individual attestation is isolated: it is recorded in the report
  and the remaining attestations are still evaluated.
* A required type that is absent is named in `missingRules` and in the error.
* "No attestations exist" and "attestations could not be fetched" are
  distinct outcomes.

## Offline evaluation from a cache

`--attestation-policy-cache <DIR>` stores the fetched bundles. If the registry
is later unreachable, cached bundles are re-verified and evaluated, and the
report's `cache` block records `used`, `cachedAt`, `ageSeconds` and `stale`.
Evidence served this way is always marked stale.

A cached fallback is used only for retrieval failures. A bundle that fails
signature or identity verification is never replaced by cached evidence, and
an image that definitively has no attestations is not masked by the cache.
