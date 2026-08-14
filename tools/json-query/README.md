# json-query

Tier-0 Synapse tool. Parse + navigate/reshape JSON via a dotted path (jq-lite).
Pure compute. `wasm32-wasip2`; args JSON at argv[0]; `network_mode: none`.

## Args
```json
{ "input": <json or json-string>, "query": "a.b.0.c", "keys": false }
```
Or read from a file: `{ "path_file":"/work/x.json", "query":"..." }`.
Numeric path segment = array index. `keys:true` adds object keys / array length
at the resolved node. Unresolvable path → `matched:false` (not an error).
