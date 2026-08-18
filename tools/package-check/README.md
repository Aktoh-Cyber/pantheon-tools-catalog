# package-check

Host-API Synapse tool (Tier 2). Built as a plain `wasm32-wasip2` command with
`wit-bindgen::generate!` importing exactly one M11 provider interface — see `wit/world.wit`.
Host WIT mirrored in `wit/deps/synapse-host/` from `synapse/crates/synapse-host/wit/`.

See the module doc in `src/main.rs` for the args/output contract and the required
`host_apis` grant. Follows the node-tool ExitCode contract (never `process::exit`).
