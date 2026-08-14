# text-entropy

Tier-0 Synapse tool. Shannon entropy + text stats — a cheap first-pass signal
for secret-scan / malware triage. `wasm32-wasip2`; args JSON at argv[0];
`network_mode: none`. `high_entropy` flags entropy > 4.8 bits/byte (the
detect-secrets/truffleHog threshold; catches base64/hex tokens too).

## Args
```json
{ "text": "<string>" }   // or  { "path": "/work/x", "max_bytes": 1048576 }
```
Output: `shannon_entropy`, `normalized_entropy`, `printable_ratio`,
`distinct_bytes`, `lines`, `words`, `high_entropy`.
