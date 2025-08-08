#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(pwd)"
AGENT_DIR="agent"
SUBCRATE_DIR="$AGENT_DIR/wasm-crate"   # dipakai jika agent = workspace
CRATE_DIR="$AGENT_DIR"                 # default
HOST_WASM_PATH="host/src/agent_template.wasm"

COMMIT_MSG=${1:-"chore: auto build wasm & commit"}
PUSH=${PUSH:-"false"}          # PUSH=true untuk auto-push
BRANCH=${BRANCH:-""}           # contoh: BRANCH=main
RUN_HOST=${RUN_HOST:-"false"}  # RUN_HOST=true untuk npm start

# ===== 0) ENV (.env kalau ada) =====
[ -f ".env" ] && set -o allexport && source .env && set +o allexport

# ===== 0.1) Perbaiki nama file salah: cargo.tml -> Cargo.toml =====
find . -type f -iname "cargo.tml" -exec bash -c '
  for f; do
    d=$(dirname "$f")
    if [ -f "$d/Cargo.toml" ]; then
      echo "ℹ️  Skip rename (sudah ada): $d/Cargo.toml"
    else
      mv "$f" "$d/Cargo.toml"
      echo "✅ Renamed: $f -> $d/Cargo.toml"
    fi
  done
' bash {} +

# ===== 1) Deteksi apakah agent/Cargo.toml adalah workspace =====
IS_WORKSPACE="false"
if [ -f "$AGENT_DIR/Cargo.toml" ]; then
  if grep -q '^\[workspace\]' "$AGENT_DIR/Cargo.toml" && ! grep -q '^\[package\]' "$AGENT_DIR/Cargo.toml"; then
    IS_WORKSPACE="true"
  fi
fi

# ===== 2) Siapkan crate WASM =====
init_crate_minimal () {
  local dir="$1"
  mkdir -p "$dir/src"
  if [ ! -f "$dir/Cargo.toml" ]; then
    cat > "$dir/Cargo.toml" <<'TOML'
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
    echo "✅ Created $dir/Cargo.toml"
  fi
  if [ ! -f "$dir/src/lib.rs" ]; then
    cat > "$dir/src/lib.rs" <<'RS'
// minimal stub — isi logic kamu nanti
#[no_mangle]
pub extern "C" fn run() {}
RS
    echo "✅ Created $dir/src/lib.rs"
  fi
}

if [ "$IS_WORKSPACE" = "true" ]; then
  echo "ℹ️  agent/ adalah WORKSPACE → pakai sub-crate: $SUBCRATE_DIR"
  init_crate_minimal "$SUBCRATE_DIR"
  CRATE_DIR="$SUBCRATE_DIR"
else
  echo "ℹ️  agent/ adalah CRATE biasa"
  init_crate_minimal "$AGENT_DIR"
  CRATE_DIR="$AGENT_DIR"
fi

# ===== 3) Toolchain Rust =====
command -v rustup >/dev/null || { echo "❌ rustup belum terpasang"; exit 1; }
source "$HOME/.cargo/env" 2>/dev/null || true
rustup default stable >/dev/null || rustup default stable
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

# ===== 4) Build WASM =====
echo "🚧 Building WASM di $CRATE_DIR ..."
( cd "$CRATE_DIR" && cargo build --release --target wasm32-unknown-unknown )

# Tentukan target dir: per-crate atau workspace root
BUILD_TARGET_DIR="$CRATE_DIR/target"
[ -d "$BUILD_TARGET_DIR" ] || BUILD_TARGET_DIR="target"

# Cari artefak .wasm (urut opsi find yang benar)
WASM_OUT="$(find "$BUILD_TARGET_DIR/wasm32-unknown-unknown" -maxdepth 4 -type f -name '*.wasm' | head -n1)"
if [ -z "${WASM_OUT:-}" ] || [ ! -f "$WASM_OUT" ]; then
  echo "❌ Gagal: .wasm tidak ditemukan di $BUILD_TARGET_DIR/wasm32-unknown-unknown"
  echo "Tips: coba lihat isi:"
  echo "find $BUILD_TARGET_DIR -maxdepth 4 -type f -name '*.wasm'"
  exit 1
fi
echo "✅ WASM ditemukan: $WASM_OUT"
# ===== 5) Salin artefak ke host =====
mkdir -p "$(dirname "$HOST_WASM_PATH")"
cp "$WASM_OUT" "$HOST_WASM_PATH"
echo "✅ Copied -> $HOST_WASM_PATH"

# ===== 6) Install deps host (opsional) =====
if [ -f "host/package.json" ]; then
  ( cd host && (npm ci || npm install) )
fi

# ===== 7) Commit =====
git add -A
if git diff --cached --quiet; then
  echo "ℹ️  Tidak ada perubahan untuk di-commit."
else
  git commit -m "$COMMIT_MSG"
  echo "✅ Commit: $COMMIT_MSG"
fi

# ===== 8) Push (opsional) =====
[ -n "$BRANCH" ] && git checkout -B "$BRANCH"
if [ "$PUSH" = "true" ]; then
  CUR=$(git rev-parse --abbrev-ref HEAD)
  git push -u origin "$CUR"
  echo "🚀 Pushed ke $CUR"
fi

# ===== 9) Jalankan host (opsional) =====
if [ "$RUN_HOST" = "true" ] && [ -f "host/package.json" ]; then
  echo "▶️ Menjalankan host..."
  ( cd host && npm start )
fi

echo "Selesai ✅"
