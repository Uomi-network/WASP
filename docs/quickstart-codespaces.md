# Quickstart: Build & Test in GitHub Codespaces

## Why Codespaces?
Fast, reproducible Linux environment with stable Rust and toolchains—ideal for first successful build.

## Steps
1. Open this repository in **GitHub Codespaces**.
2. In the terminal, run:
   ```bash
   rustup target add wasm32-unknown-unknown
   cargo build --workspace --verbose
   # Optional: build any WASM (cdylib) crates for wasm32
   # cargo build -p <crate_name> --release --target wasm32-unknown-unknown
   ```

## Troubleshooting
- **`can't find library 'xxx'`** → Ensure a `src/lib.rs` exists or set `[lib] path` in that crate's `Cargo.toml`.
- **`failed to load manifest for workspace member`** → Verify the `[workspace].members` entries match actual folders.
- **Linker or toolchain mismatch** → Re-run `rustup show` and confirm `stable` is default; then `rustup update`.