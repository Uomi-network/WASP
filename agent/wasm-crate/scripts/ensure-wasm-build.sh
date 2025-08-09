#!/usr/bin/env bash
set -euo pipefail

CRATE_DIR="agent/wasm-crate"
WS_ROOT="agent/Cargo.toml"
OUT_WASM="host/src/agent_template.wasm"
MSG=${1:-"chore: ensure wasm build & commit"}
PUSH=${PUSH:-"false"}
BRANCH=${BRANCH:-""}

mkdir -p "$CRATE_DIR/src"

# --- Workspace auto-fix ---
if [ -f "$WS_ROOT" ] && grep -q '^\[workspace\]' "$WS_ROOT"; then
  # pastikan "wasm-crate" ada di members
  if grep -q '^members' "$WS_ROOT"; then
    if ! grep -q '"wasm-crate"' "$WS_ROOT"; then
      # sisipkan di array members
      awk '
        BEGIN{inm=0}
        /^\[workspace\]/{print; next}
        /^members[[:space:]]*=/{
          print;
          while (getline line){print line; if(line ~ /\[/) break}
          next
        }
        {print}
      ' "$WS_ROOT" > "$WS_ROOT.tmp"
      # cara sederhana: tambahkan setelah baris pembuka members = [
      sed -i '/^members *= *\[/a \  "wasm-crate",' "$WS_ROOT.tmp"
      mv "$WS_ROOT.tmp" "$WS_ROOT"
      echo "✅ Workspace: tambah \"wasm-crate\" ke agent/Cargo.toml"
    fi
  else
    # tidak ada members -> buat dengan wasm-crate
    awk '1; END{print "\n[workspace]\nmembers = [\n  \"wasm-crate\"\n]\n"}' "$WS_ROOT" > "$WS_ROOT.tmp" && mv "$WS_ROOT.tmp" "$WS_ROOT"
    echo "✅ Workspace: buat members dengan \"wasm-crate\""
  fi
else
  # Tidak ada workspace di agent -> buat crate berdiri sendiri
  if ! grep -q '^\[workspace\]' "$CRATE_DIR/Cargo.toml" 2>/dev/null; then
    printf '[workspace]\n\n' | cat - "$CRATE_DIR/Cargo.toml" 2>/dev/null > "$CRATE_DIR/Cargo.toml.tmp" || true
    if [ -f "$CRATE_DIR/Cargo.toml.tmp" ]; then mv "$CRATE_DIR/Cargo.toml.tmp" "$CRATE_DIR/Cargo.toml"; fi
    echo "✅ Crate opt-out: tambah [workspace] di $CRATE_DIR/Cargo.toml"
  fi
fi

# --- Pastikan Cargo.toml valid (cdylib) ---
if [ ! -f "$CRATE_DIR/Cargo.toml" ]; then
  cat > "$CRATE_DIR/Cargo.toml" <<'TOML'
[package]
name = "agent_template"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
TOML
else
  grep -q '^\[lib\]' "$CRATE_DIR/Cargo.toml" || printf '\n[lib]\ncrate-type = ["cdylib"]\n' >> "$CRATE_DIR/Cargo.toml"
  grep -q 'crate-type *= *\["cdylib"\]' "$CRATE_DIR/Cargo.toml" || sed -i '/^\[lib\]/,$ s/^crate-type.*/crate-type = ["cdylib"]/' "$CRATE_DIR/Cargo.toml"
fi

# --- Minimal lib.rs ---
[ -f "$CRATE_DIR/src/lib.rs" ] || cat > "$CRATE_DIR/src/lib.rs" <<'RS'
#[no_mangle]
pub extern "C" fn run() {}
RS

# --- Toolchain ---
command -v rustup >/dev/null || { echo "rustup belum terpasang"; exit 1; }
source "$HOME/.cargo/env" 2>/dev/null || true
rustup default stable >/dev/null || rustup default stable
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

# --- Build ---
( cd "$CRATE_DIR" && cargo clean && cargo build --release --target wasm32-unknown-unknown )

# --- Cari artifact .wasm (support workspace target) ---
TARGET_DIR="$CRATE_DIR/target"
[ -d "$TARGET_DIR" ] || TARGET_DIR="target"
WASM_PATH="$(find "$TARGET_DIR" -maxdepth 7 -type f -name '*.wasm' | head -n1 || true)"
if [ -z "${WASM_PATH:-}" ] || [ ! -f "$WASM_PATH" ]; then
  echo "❌ Tidak menemukan .wasm. Coba:"
  echo "find $TARGET_DIR -maxdepth 7 -type f -name '*.wasm'"
  exit 1
fi
echo "✅ WASM: $WASM_PATH"

# --- Copy + commit + optional push ---
mkdir -p "$(dirname "$OUT_WASM")"
cp "$WASM_PATH" "$OUT_WASM"
echo "✅ Disalin -> $OUT_WASM"

git add -A
if git diff --cached --quiet; then
  echo "ℹ️ Tidak ada perubahan untuk di-commit."
else
  git commit -m "$MSG"
  echo "✅ Commit: $MSG"
fi
[ -n "$BRANCH" ] && git checkout -B "$BRANCH"
if [ "$PUSH" = "true" ]; then
  CUR=$(git rev-parse --abbrev-ref HEAD)
  git push -u origin "$CUR"
  echo "🚀 Pushed ke $CUR"
fi
echo "Selesai ✅"
