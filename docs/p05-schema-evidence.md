# Frozen 136-tool schema evidence

`tests.p05_current_schema.validate_current` checks the frozen 136-tool table
against both complete input/output schema projections. It is an offline evidence
helper; it does not change activation, issuer, consumer or live service behavior.

The public schema fixture was captured through the formal SDK in T013/R04 on
2026-09-27, against implementation `a946ecac863612864dacc4419ca74c857afa5f82`.
It retains only names and input/output schemas, without credentials, transport
headers, session IDs or local evidence paths. This is a historical observation,
not proof of a future Phase or current runtime qualification.

| Domain | Sorted JSON row keys | Ending | SHA-256 |
| --- | --- | --- | --- |
| P05 Phase | name, inputSchema, outputSchema | LF | c9ac2929b125c16391810c196222e6e93730ff1828c841e2ee4aa4be42955575 |
| Diagnostic | name, input, output | no LF | f2dee4a593bc6158c4576cd8e5b36929487901c5e95b7049b40b888765465b57 |

Both use UTF-8, sorted object keys, compact JSON and unescaped Unicode. The
payloads represent the same schemas but are different byte domains; their
hashes must never be substituted. A changed schema requires a separately
reviewed fixture and identity update, not replacement of constants in tests.

Run `.venv/bin/python -m unittest tests.test_p05_current_schema -v`.
Regression cases cover changed input/output schemas, missing/extra/duplicate
names, missing output schema, reordered tools, missing LF and cross-domain
substitution. The fixture includes public artifact defaults, not collected data.
