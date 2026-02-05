#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-target}"
N="${N:-7}"
T="${T:-4}"

rm -rf "$ROOT/party_"* "$ROOT/server" "$ROOT/public.json" "$ROOT/partials"
mkdir -p "$ROOT/partials"

# DKG init for all parties
for i in $(seq 1 "$N"); do
  cargo run --release --bin mempool-encrypt -- dkg-init --id "$i" --n "$N" --t "$T" --root "$ROOT"
done

# Deliver outbox messages to their intended recipients
for i in $(seq 1 "$N"); do
  cargo run --release --bin mempool-encrypt -- deliver-outbox --from "$i" --root "$ROOT"
done

# Handle inboxes
for i in $(seq 1 "$N"); do
  cargo run --release --bin mempool-encrypt -- dkg-handle --id "$i" --root "$ROOT"
done

# Verify shares (complaints if any)
for i in $(seq 1 "$N"); do
  cargo run --release --bin mempool-encrypt -- dkg-verify --id "$i" --root "$ROOT"
done

# Deliver complaints / share opens
for i in $(seq 1 "$N"); do
  cargo run --release --bin mempool-encrypt -- deliver-outbox --from "$i" --root "$ROOT"
done

# Handle complaint opens
for i in $(seq 1 "$N"); do
  cargo run --release --bin mempool-encrypt -- dkg-handle --id "$i" --root "$ROOT"
done

# Finalize
for i in $(seq 1 "$N"); do
  cargo run --release --bin mempool-encrypt -- dkg-finalize --id "$i" --root "$ROOT"
done

# Merge public params
cargo run --release --bin mempool-encrypt -- public-merge --root "$ROOT" --n "$N" --out "$ROOT/public.json"

# Encrypt
TAG_B64=$(python3 - <<'PY'
import base64
print(base64.b64encode(b'demo-tag').decode())
PY
)

printf "hello" > "$ROOT/plain.txt"

cargo run --release --bin mempool-encrypt -- encrypt --pub "$ROOT/public.json" --tag "$TAG_B64" --in "$ROOT/plain.txt" --out "$ROOT/cipher.txt"

# Partial releases from first T parties
rm -rf "$ROOT/partials" && mkdir -p "$ROOT/partials"
for i in $(seq 1 "$T"); do
  cargo run --release --bin mempool-encrypt -- partial-release --secret "$ROOT/party_$(printf '%02d' "$i")/secret.json" --pub "$ROOT/public.json" --tag "$TAG_B64" --out "$ROOT/partials/partial_${i}.b64"
done

# Combine
cargo run --release --bin mempool-encrypt -- combine --tag "$TAG_B64" --partials "$ROOT/partials" --pub "$ROOT/public.json" --out "$ROOT/witness.b64"

# Decrypt
cargo run --release --bin mempool-encrypt -- decrypt --pub "$ROOT/public.json" --tag "$TAG_B64" --ct "$ROOT/cipher.txt" --witness "$ROOT/witness.b64" --out "$ROOT/plain_out.txt"

echo "Decrypted: $(cat "$ROOT/plain_out.txt")"
