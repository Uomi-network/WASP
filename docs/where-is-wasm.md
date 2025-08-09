# Where to find the built `.wasm`

There are two common locations:

1. **Cargo target output** (when building a cdylib crate for `wasm32`):
   ```
   target/wasm32-unknown-unknown/release/<crate_name>.wasm
   ```

2. **Project-specific locations** used by templates or hosts (if any).
   Check this repository’s documentation or the host crate's README for custom paths.

> Tip: After enabling the CI workflow in this pack, built `.wasm` files will also be uploaded as **GitHub Actions Artifacts** for each push/PR.