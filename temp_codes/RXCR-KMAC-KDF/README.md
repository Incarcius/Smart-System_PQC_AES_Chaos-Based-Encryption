# RXCR-KMAC KDF

RXCR-KMAC KDF is a custom **extract–then–expand** key derivation construction
designed for high-entropy KEM shared secrets in post-quantum settings.[file:283][web:324]

The design is **inspired by the extract–then–expand structure of HKDF**, but it
is a distinct KDF with its own extractor and expander:[file:283]

- **RXCR-Extract**: a custom non-linear extractor with a SHA3‑256 finalizer.
- **KMACXOF256**: an NIST SP 800‑185 XOF-based expand step.[file:283]

The construction is tuned for PQ‑KEM secrets and multi-key per-node derivation,
and is meant to be read together with the accompanying paper that specifies and
analyzes the design.[file:283]

---

## 1. Design overview

### 1.1 RXCR‑Extract

RXCR‑Extract takes `(ikm, salt)` and outputs a 32‑byte pseudorandom key `PRK`.[file:283]

- `ikm`: input key material, assumed to be high-entropy and KEM‑uniform
  (for example a post‑quantum KEM shared secret).
- `salt`: context string (for example `NodeID || timestamp || protocol_tag`).[file:283]

Conceptually, RXCR‑Extract plays the “extract” role in an extract–then–expand
pipeline, but it is not HMAC‑based and is structured around a rotational,
byte‑oriented mixing core.[file:283]

High‑level steps:[file:283]

1. **Input preparation**

   - Pad `ikm` and `salt` to the same length, at least 32 bytes.
   - Initialize:
     - `state`: 32‑byte array of zeros.
     - `p_prev = 0x5A` (a fixed, public chain seed).

2. **Per‑byte base mix**

   For each byte position `j`:

   - `x0_j = IKM_j XOR salt_j`  
     (entangles `ikm` and `salt` bytewise).

3. **Non‑linear chaining**

   For each `j`:

   - `t_j  = x0_j AND p_prev`
   - `x1_j = x0_j XOR p_prev XOR ROTL8(t_j, 1)`

   This introduces non‑linearity via the `AND` term and couples each byte
   to all previous bytes via `p_prev`.[file:283]

4. **Positional rotation**

   - `shift_j = (i + j) mod 8`, where `i` is the window index and `j` the
     byte index within the window.
   - `p_j = ROTL8(x1_j, shift_j)`
   - Update `p_prev = p_j`.[file:283]

5. **Rotational fan‑out into state**

   Each `p_j` is injected into all 32 bytes of `state`:

   - For `m` in `0..31`:
     - `state[m] ^= ROTL8(p_j, (shift_j + m) mod 8)`.[file:283]

6. **Full‑state non‑linear mixing**

   Two passes over the 32‑byte state ring:[file:283]

   - Pass 1 — forward (right neighbour):

     - For `m` in `0..31`:
       - `t = state[m] AND state[(m+1) mod 32]`
       - `state[m] = ROTL8(state[m] XOR t, m mod 8)`

   - Pass 2 — backward (left neighbour):

     - For `m` in `31..0`:
       - `t = state[m] AND state[(m-1) mod 32]`
       - `state[m] = ROTL8(state[m] XOR t, (m+1) mod 8)`.

7. **SHA3‑256 finalizer**

   After all windows have been processed:

   - `PRK = SHA3‑256(state || IKM || salt)`.[file:283]

`PRK` is the sole output of RXCR‑Extract and is used as the key
for the KMACXOF256 expand phase.[file:283]

### 1.2 KMACXOF256 expand

Given a 32‑byte `PRK`, the expand phase uses KMACXOF256 (from NIST SP 800‑185)
to derive variable‑length output keying material.[file:283]

Typical parameterization:[file:283][web:208]

- `key`    = `PRK`
- `data`   = `info || counter` (to separate multiple outputs)
- `custom` = `node_id || ":" || algo` (for node and algorithm separation)

This fills the “expand” role in the construction, providing as many bytes of
output as required for a given node and algorithm set.[file:283]

---

## 2. Repository layout

Current layout (Python is the reference implementation):[file:286][file:283]

```text
RXCR-KMAC-KDF/
├─ README.md
├─ LICENSE
├─ pyproject.toml            # reserved for future packaging
├─ .gitignore
├─ python/
│  ├─ rxcr.py                # RXCR-Extract (RXCR-SHA3-256)
│  ├─ kmac.py                # KMACXOF256 implementation
│  ├─ kdf.py                 # High-level RXCR-KMAC KDF API
│  ├─ __init__.py
│  └─ tests/
│     ├─ __init__.py
│     ├─ temp.py             # Python tests / validation harness
│     ├─ kem_generate_ikm.py # ML-KEM helper to generate IKM
│     └─ sts/
│        ├─ data/            # STS / KEM input data (generated)
│        ├─ results/
│        └─ vendor/
├─ c/
│  ├─ include/               # Planned C API headers
│  ├─ src/                   # Planned C reference implementation
│  └─ tests/                 # Planned C test/benchmark code
└─ examples/
   ├─ pq_node_demo.py        # interactive RXCR-KMAC pipeline demo
   └─ pq_node_demo.c
```

The Python implementation is the reference model and should be considered
authoritative for the algorithm’s behaviour; the planned C implementation under
`c/` is intended to mirror the Python semantics and provide a lower‑level
integration path.[file:283]

---

## 3. Post‑quantum KEM setup (liboqs)

RXCR‑KMAC is intended to sit *after* a post‑quantum KEM; this repo does **not**
bundle a KEM implementation but integrates cleanly with liboqs.[web:208][web:278]

### 3.1 Build and install liboqs

Follow the liboqs docs to clone and build from source, then install into
a local prefix (example below uses `~/.local`).[web:213]

```bash
cd /mnt/e/GIthub-Repos
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build

cmake -G"Ninja" \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_USE_OPENSSL=OFF \
  -DCMAKE_INSTALL_PREFIX=$HOME/.local ..
ninja
ninja install
```

Confirm the library is installed:

```bash
ls ~/.local/lib | grep oqs
# Expect: liboqs.a, liboqs.so, liboqs.so.<version>, ...
```

Export the library path (add to your shell profile as needed):[web:307]

```bash
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"
```

### 3.2 Install liboqs‑python (`oqs`)

The Python bindings are a separate package that depend on the `liboqs` build.[web:288]

```bash
cd /mnt/e/GIthub-Repos
git clone https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
python3 -m pip install .
```

Quick check:

```bash
python3 -c "import oqs; print('oqs import ok')"
```

You may see a warning if the liboqs and liboqs‑python minor versions differ;
this is a warning only and not a hard error.[web:325]

---

## 4. Generating ML‑KEM IKM for RXCR

For convenience, the repo includes a small helper that uses liboqs‑python to
generate an ML‑KEM‑768 keypair and dump it as JSON; the shared secret from a
real KEM handshake is what RXCR‑Extract expects as high‑entropy `ikm` in
production, but for testing it is useful to have a reproducible generator.[web:207][web:324]

Script: `python/tests/kem_generate_ikm.py`.[file:301]

Run from the repo root:

```bash
cd RXCR-KMAC-KDF
python3 python/tests/kem_generate_ikm.py
```

This will write:

```text
python/tests/sts/data/kem_keypair.json
```

The JSON structure:

```json
{
  "algorithm": "ML-KEM-768",
  "public_key_b64": "<Base64 public key>",
  "secret_key_b64": "<Base64 secret key>"
}
```

- `public_key_b64` can be distributed to peers.
- `secret_key_b64` must be kept private; it is not committed to the repo
  and the `data/` directory is intended for local/generated material
  only.

You can decode `secret_key_b64` in Python and feed it into RXCR‑Extract
as `ikm` when modelling KEM‑derived sessions.

---

## 5. Python usage (reference implementation)

### 5.1 Basic RXCR‑KMAC usage

From the repository root (ensure `python/` is on `sys.path`, e.g. by running
from the root or adding `python` to `PYTHONPATH`):[file:283]

```bash
cd RXCR-KMAC-KDF
python3
```

Example:

```python
from python import rxcr, kdf  # or adjust to your package layout

# Example inputs
ikm  = b"\x00" * 32           # example KEM shared secret (replace in real use)
salt = b"node01|ts|v1"        # NodeID || timestamp || tag
info = b"pq-iot:v1"

nodes = [
    {"nodeid": b"node_0001", "algo": "AES-GCM", "keylen": 32},
    {"nodeid": b"node_0001", "algo": "SPECK",   "keylen": 16},
]

# Extract-only: RXCR-Extract + SHA3-256
prk = rxcr.rxcr_extract(ikm, salt)
print("PRK length:", len(prk))

# Full KDF: derive per-node, per-algorithm keys
keys = kdf.rxcr_kdf(ikm, salt, info, nodes)
for nid, key in keys.items():
    print(nid, len(key), key.hex())
```

The exact function names and parameter shapes follow the reference Python
implementation in `rxcr.py` and `kdf.py`; see those files and
`examples/pq_node_demo.py` for more detailed CLI usage and argument formats.[file:283]

### 5.2 Using the KEM‑generated IKM

If you generated `kem_keypair.json`, you can load and use the secret key
as `ikm` in a quick experiment:

```python
import base64, json
from pathlib import Path
from python import rxcr

data = json.loads(
    Path("python/tests/sts/data/kem_keypair.json").read_text()
)
ikm = base64.b64decode(data["secret_key_b64"])
salt = b"node01|ts|rxcr-v1"

prk = rxcr.rxcr_extract(ikm, salt)
print("PRK len:", len(prk))
print("PRK hex:", prk.hex())
```

This shows how to connect a PQ‑KEM‑derived secret into the RXCR‑KMAC KDF
pipeline.

---

## 6. Tests (Python)

All current Python tests and validation helpers are collected in:[file:283]

- `python/tests/temp.py`

To run them:

```bash
cd RXCR-KMAC-KDF
python3 -m python.tests.temp
```

The test suite (as it evolves) includes:[file:283]

- Keccak core checks against `hashlib` for SHAKE256 and SHA3‑256 where
  available.
- KMACXOF256 tests for determinism, input sensitivity, and context separation.
- RXCR‑Extract tests for local avalanche behaviour and basic distribution
  sanity.
- End‑to‑end KDF tests for determinism and stability across versions.

Additional statistical tests on streams of `PRK` or expanded keys can be
run by generating data with the reference implementation and feeding it into
external randomness / STS harnesses under `python/tests/sts/`.[file:283]

---

## 7. C implementation and benchmarking

The `c/` directory is reserved for a C reference implementation of the same
construction:[file:283]

- `include/`: public headers for RXCR‑Extract, KMACXOF256, and the combined KDF.
- `src/`: C implementations that mirror the Python reference logic byte‑for‑byte.
- `tests/`: C tests using Python‑generated test vectors, plus benchmarks.

Intended flow:[file:283]

1. Finalize Python test vectors (fixed `(ikm, salt, prk, okm)` tuples).
2. Implement the C version and verify that it matches Python outputs exactly.
3. Run microbenchmarks on target platforms (for example embedded boards,
   Raspberry Pi‑class devices).

---

## 8. Security scope

- RXCR‑KMAC KDF is designed for **high‑entropy KEM‑derived secrets**, such as
  post‑quantum KEM shared secrets.[file:283][web:324]
- It is **not** intended as a password KDF or for other low‑entropy sources.[file:283]
- The construction, its assumptions, and its security goals are described in
  the accompanying paper; this repository provides a reference implementation
  of that design.[file:283]
- Standard KDFs (for example HKDF as per RFC 5869) remain appropriate where
  their assumptions and properties match the application’s needs.[file:283]

Use RXCR‑KMAC KDF in contexts where its structure and assumptions align with
your protocol design and the guidance given in the paper.[file:283]