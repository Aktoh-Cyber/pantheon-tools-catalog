# fs-grep

Tier-0 Synapse tool. Regex content search across files — the workhorse for
incident response + threat hunting inside a mounted tree. Uses `regex-lite`
(small, no look-around/backrefs). `wasm32-wasip2`; args JSON at argv[0];
`network_mode: none`, no `host_apis`. Binary/oversized files skipped.

## Args
```json
{ "root":"/work", "pattern":"<regex>", "name_glob":"*.log",
  "ignore_case":false, "max_matches":500, "max_file_bytes":1048576, "max_depth":20 }
```
Output: `matches:[{path,line,text}]` + `truncated`. Bad regex → error, exit 1.
