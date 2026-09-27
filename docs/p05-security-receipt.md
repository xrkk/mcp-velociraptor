# Offline P05 security command receipt

`tests.p05_security_receipt.inspect_receipt` is a non-activating, read-only inspector for `p05-security-command-receipt-v1` as specified by [the JSON Schema](p05-security-receipt.schema.json). Its result is **receipt consistency**, never Phase admission. It is separate from the unadopted existing-189 causal event sequence. It does not change P05 issuer, public verifier, consumer, service, or canonical state.

Call it with a bundle directory, an exact `{path,size,sha256}` Ref for the receipt, and an **independently supplied** trusted-context object. The object must contain `receipt_sha256`, approved `collector_sha256` and collector instance, run/restore/VM/boot/service identities, network/READY/source/implementation/formal tools-schema hashes, ACL/root hashes, transfer-policy state/hash, fixed IP/source/port, tool count, and exact `command_argv` for all six labels. All fields are mandatory; absent transfer policy is explicitly `transfer_policy_enabled: false` and `transfer_policy_sha256: null`. This is legal: the six transfer tools remain registered, with capabilities disabled and other calls returning `transfer_disabled`. An enabled policy requires its independently pinned hash. `collector_sha256` names an approved collector but a string alone does not prove the collector executed.

The receipt stores six ordered **collector command responses** (`service`, `policy`, `acl`, `entry`, `schema`, `network`). The inspector validates exact JSON shape and identities, zero exit/empty stderr, stdout hashes, parsed semantic fields, and byte Refs for separately retained SDK and WFP originals. For the existing HTTP contract it requires no-Origin success 200, missing/wrong Bearer 401, **wrong Host 421**, wrong Origin 403. The P05 raw HTTP entry verifier in `tests.p05_http_evidence` remains responsible for request/response and handler-counter semantics; a status summary or this receipt cannot replace its originals. Likewise, SDK and WFP Refs prove only byte retention. This inspector does not parse native SDK exchanges or WFP 5152 events, verify protected filesystem provenance or actual collector execution, establish network-window completeness, or prove a Phase. A collector-authored `PASS`, a self-signed hash chain, or a copied command stdout cannot establish those facts.

Offline command (no secret or network access):

```bash
.venv/bin/python -m tests.p05_security_receipt \
  --bundle /path/to/evidence-copy \
  --receipt-ref /path/to/independently-pinned-ref.json \
  --trusted-context /path/to/independently-approved-context.json
```

The trusted context must come from an independent approval/source verification path, not be copied from the receipt. A successful command prints `phase_admission: false` and `native_provenance_verified: false`; refusal exits 2. Tests use only fictional IDs/IPs and synthetic originals: `.venv/bin/python -m unittest tests.test_p05_security_receipt -v`.
