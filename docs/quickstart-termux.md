# Quickstart: Build on Termux (Android)

**Tip:** Do your first successful build in Codespaces, then continue on Termux.

## Install
```bash
pkg update && pkg upgrade -y
pkg install git clang cmake rust python -y
```

## Build
```bash
# If rustup is available on your device:
rustup default stable || true
rustup target add wasm32-unknown-unknown || true

# Build the workspace (native)
cargo build --workspace --verbose

# Optional: build WASM crates (cdylib) for wasm32
# cargo build -p <crate_name> --release --target wasm32-unknown-unknown
```

## Troubleshooting
- **`can't find library 'xxx'`** → Ensure `src/lib.rs` exists or set `[lib] path` in that crate's `Cargo.toml`.
- **`failed to load manifest for workspace member`** → Fix paths in `[workspace].members` at the repo root.
- **`error: rustup could not choose a version`** → Install `rust` from Termux packages, or set default toolchain with `rustup default stable`.