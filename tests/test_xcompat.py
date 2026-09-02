"""Cross-compat harness (Phase 1.5): pin Python's KAT vectors into Rust,
then assert Rust reproduces them bit-for-bit.

The harness sits between the two implementations:

  Python (test data)        Rust (oracle)
  -----------------         -------------
  seed2bin KAT   ----JSONL--->   seed2bin
                  <---PASS/FAIL----
  verify_sig KAT ----JSONL--->   verify_signature
                  <---PASS/FAIL----

If Rust and Python ever diverge on a `seed2bin` or signature
verification input, this test fails with the expected vs actual bytes
printed for triage. The harness is intentionally symmetric: a buggy
`sign_hash` or `sign_data` on the Python side surfaces here as a
verification failure — the signature would be over the wrong digest,
and the Rust oracle (which derives the same key from the same seed)
would refuse it.

`KAT_CHECK_BIN` overrides the path to the Rust binary so CI can pin a
specific build; the default looks for `kat_check` next to the working
tree's `yubtc-xcompat/target/release/examples/`.

Wire format (one JSON object per line):

  seed2bin   -- {"seed", "nonce", "passphrase", "kdf", "expected"}
  verify_sig -- {"type": "verify_sig", "seed", "nonce", "passphrase",
                 "kdf", "datahash", "signature"}

`type` is optional for `seed2bin` vectors (backwards compatibility with
rows written before the field existed); `verify_sig` rows must set
`type` explicitly so the dispatch never gets it wrong.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest


# Default path to the Rust harness binary. The location assumes the
# yubtc-python repo and yubtc repo (which carries the Rust core and
# the `kat_check` example) sit side-by-side under the same parent,
# which is the standard local layout.
_DEFAULT_KAT_CHECK_BIN = str(
    Path(__file__).resolve().parents[2]
    / 'yubtc'
    / 'target'
    / 'release'
    / 'examples'
    / 'kat_check'
)


def _kat_check_bin() -> str:
    return os.environ.get('KAT_CHECK_BIN', _DEFAULT_KAT_CHECK_BIN)


def _kat_check_available() -> bool:
    return Path(_kat_check_bin()).is_file()


# ---------------------------------------------------------------------------
# The KAT table the harness verifies. Same rows as test_seed2bin_kdf_*_kat
# but serialised as JSONL so the Rust side can read it directly. Empty
# rows (yubtc+passphrase or pbkdf2+empty) are excluded because they
# raise upstream rather than producing a 32-byte output -- a divergence
# in those error paths is caught by test_seed2bin_*_rejects_*, not here.
# ---------------------------------------------------------------------------

KAT_SEED = ('abandon abandon abandon abandon abandon abandon abandon '
            'abandon abandon abandon abandon about')

KAT_ROWS = [
    # yubtc, empty passphrase
    {'seed': KAT_SEED, 'nonce': 0, 'passphrase': '', 'kdf': 'yubtc',
     'expected': 'e47a0307ca0c0415fea1fdf37816950f7b337a9f1822313770c76d102180a548'},
    {'seed': KAT_SEED, 'nonce': 1, 'passphrase': '', 'kdf': 'yubtc',
     'expected': '7e12ff0b367a9f6918ddd0dffddd88dacedfdd30d4566d40e52bd74b4592fb36'},
    {'seed': KAT_SEED, 'nonce': 7, 'passphrase': '', 'kdf': 'yubtc',
     'expected': '2881ba672ae52ead2ade2ebf845f6c762578366866f327dc40fa30cd557af8c7'},
    # pbkdf2, hunter2
    {'seed': KAT_SEED, 'nonce': 0, 'passphrase': 'hunter2', 'kdf': 'pbkdf2',
     'expected': '377b9f0c4cedfe7816f79a1bac8406772192c32487171928d9d15f0cd7262a8f'},
    {'seed': KAT_SEED, 'nonce': 1, 'passphrase': 'hunter2', 'kdf': 'pbkdf2',
     'expected': 'f5206f58f97f4ebad7724f295157b75f68e57bd3cc566e4a30e9bc50c52a0a76'},
    {'seed': KAT_SEED, 'nonce': 7, 'passphrase': 'hunter2', 'kdf': 'pbkdf2',
     'expected': 'fa12b7ba0c1b4a1b462ecda99f86c965eff85aec256d1229cabee3edcde97b71'},
    # pbkdf2, test-pass
    {'seed': KAT_SEED, 'nonce': 0, 'passphrase': 'test-pass', 'kdf': 'pbkdf2',
     'expected': 'f0390b6b882c2209b459c3289dba7da8eaf72a925ff2231380a7fb6e16f85edf'},
    {'seed': KAT_SEED, 'nonce': 1, 'passphrase': 'test-pass', 'kdf': 'pbkdf2',
     'expected': '7788f1f1013c617110bba7255ba047d5ba913a772c567d2362891fafe2b14a43'},
    {'seed': KAT_SEED, 'nonce': 7, 'passphrase': 'test-pass', 'kdf': 'pbkdf2',
     'expected': 'a7d35f92b15cd9f02a7f6e02bf8b246f16930fd02cac243ee660a0e0b502517d'},
    # argon2id, hunter2
    {'seed': KAT_SEED, 'nonce': 0, 'passphrase': 'hunter2', 'kdf': 'argon2id',
     'expected': '207cdc4fab7c3882f57ca55b98b52f0c5dbfe8ecf40bba720815d3ea0aa7ca95'},
    {'seed': KAT_SEED, 'nonce': 1, 'passphrase': 'hunter2', 'kdf': 'argon2id',
     'expected': '6ffcfad60b6ff650b405af80042b65c91e86ed9ff553a23b8d6660c93bf28837'},
    {'seed': KAT_SEED, 'nonce': 7, 'passphrase': 'hunter2', 'kdf': 'argon2id',
     'expected': '54ef14f39ffc708b7afa5139b00f6739b2e8c3019d49698c82a891b6a6916961'},
    # argon2id, test-pass
    {'seed': KAT_SEED, 'nonce': 0, 'passphrase': 'test-pass', 'kdf': 'argon2id',
     'expected': '0cb06e1385a6cdc87b8d8779d36282e90dff488c954aa9ed0443bb02a2253a03'},
    {'seed': KAT_SEED, 'nonce': 1, 'passphrase': 'test-pass', 'kdf': 'argon2id',
     'expected': 'c9d06be66d8192e08150b325be6cc5133fc9d3e585b62c85bb1f92de9d3c0ee8'},
    {'seed': KAT_SEED, 'nonce': 7, 'passphrase': 'test-pass', 'kdf': 'argon2id',
     'expected': '874fdc3c720a13ac7e724a6eeb7dab4542e354dfd163122aac674c27d9d211c6'},
    # scrypt, hunter2 (scrypt v2: salt b'yubtc-scrypt-v2\x00', N=2^15/r=16)
    {'seed': KAT_SEED, 'nonce': 0, 'passphrase': 'hunter2', 'kdf': 'scrypt',
     'expected': '616b39ec565e5ffd3c927a192de22b53e6dbd01f327527cbdb64b6a18b2c6f00'},
    {'seed': KAT_SEED, 'nonce': 1, 'passphrase': 'hunter2', 'kdf': 'scrypt',
     'expected': 'd153894bdc2928bf370069808810919dca7a6dae35b6562a9521af9a378fe54f'},
    {'seed': KAT_SEED, 'nonce': 7, 'passphrase': 'hunter2', 'kdf': 'scrypt',
     'expected': '34eb461c7b1a944a1a0a49a0ad5cf1d1e0d8f9c1da58999d346975b265ac1e63'},
    # scrypt, test-pass (scrypt v2: salt b'yubtc-scrypt-v2\x00', N=2^15/r=16)
    {'seed': KAT_SEED, 'nonce': 0, 'passphrase': 'test-pass', 'kdf': 'scrypt',
     'expected': 'afeacdb5cc3981ab8b86fe563d5222456d19e0dfa6f27ced45b5004c40e0ff77'},
    {'seed': KAT_SEED, 'nonce': 1, 'passphrase': 'test-pass', 'kdf': 'scrypt',
     'expected': '0cfcb70123b1e6461b7f8cad312c00e40e3ecc1423c02ac4e47d181f99136914'},
    {'seed': KAT_SEED, 'nonce': 7, 'passphrase': 'test-pass', 'kdf': 'scrypt',
     'expected': '7d4c82f5d7b9179ae20502153501dad6457f6385c593fd9694db44c3b23ef74b'},
]


def _build_payload() -> str:
    return '\n'.join(json.dumps(row) for row in KAT_ROWS) + '\n'


# ---------------------------------------------------------------------------
# verify_sig payload: Python signs a digest with `sign_hash` and a raw
# buffer with `sign_data`, then we hand the (digest, sig) pair to Rust
# for verification. The Rust side re-derives the same privkey/pubkey
# from the same (seed, nonce, passphrase, kdf), so any silent change in
# Python's signing primitive (wrong hash function, extra SHA-256,
# swapped argument) shows up as a verification failure.
#
# Why both `sign_hash` and `sign_data` exercise the same wire format:
# the harness only sees a 32-byte digest + a DER signature. The caller
# decides what to put in `datahash`:
#   - sign_hash test → datahash is the 32-byte input we passed to sign_hash
#   - sign_data test → datahash is sha256(sha256(raw_data)) computed here
# If Python's sign_data ever inserted an extra SHA-256, the resulting
# signature would be over sha256(sha256(sha256(sha256(raw)))) and the
# harness would refuse it (verification against the precomputed double-
# SHA256 fails). Same for sign_hash if it silently pre-hashed its input.
# ---------------------------------------------------------------------------

VERIFY_SIG_DATAHASH = bytes(range(32))  # 0x00, 0x01, ..., 0x1f
VERIFY_SIG_RAW_DATA = b'yubtc sign_data test vector\n\x00\x01'


def _build_verify_sig_rows():
    """Build the verify_sig payload by actually signing with Python.

    Each (kdf, nonce) pair produces two rows: one signed via
    `sign_hash` (datahash is the raw 32-byte input) and one signed
    via `sign_data` (datahash is sha256(sha256(raw))). The Python
    signing happens here, at module-import time, so a bug in
    `sign_hash`/`sign_data` cannot pass silently — the failing
    signature is generated, handed to Rust, and Rust refuses to
    verify it.
    """
    from yubtc.crypto import (
        KDF_ARGON2ID, KDF_PBKDF2, KDF_SCRYPT, KDF_YUBTC,
        seed2privkey, sign_data, sign_hash,
    )
    from yubtc.hash import sha256

    rows = []
    # (kdf, passphrase) tuples — yubtc only with empty passphrase, the
    # other three with a non-empty passphrase. Each combo exercises a
    # distinct derivation path on the Rust side.
    kdf_pass_pairs = [
        (KDF_YUBTC, ''),
        (KDF_PBKDF2, 'hunter2'),
        (KDF_ARGON2ID, 'hunter2'),
        (KDF_SCRYPT, 'hunter2'),
    ]
    for kdf, passphrase in kdf_pass_pairs:
        for nonce in (0, 1, 7):
            privkey = seed2privkey(
                seed=KAT_SEED, nonce=nonce, passphrase=passphrase, kdf=kdf)

            # sign_hash: signature is over VERIFY_SIG_DATAHASH directly.
            sig = sign_hash(privkey=privkey, datahash=VERIFY_SIG_DATAHASH)
            rows.append({
                'type': 'verify_sig',
                'seed': KAT_SEED,
                'nonce': nonce,
                'passphrase': passphrase,
                'kdf': kdf,
                'datahash': VERIFY_SIG_DATAHASH.hex(),
                'signature': sig.hex(),
            })

            # sign_data: signature is over sha256(sha256(raw_data)).
            # Compute the digest here so the harness verifies against
            # the same bytes Python's sign_data is expected to use.
            digest = sha256(sha256(VERIFY_SIG_RAW_DATA))
            sig = sign_data(privkey=privkey, data=VERIFY_SIG_RAW_DATA)
            rows.append({
                'type': 'verify_sig',
                'seed': KAT_SEED,
                'nonce': nonce,
                'passphrase': passphrase,
                'kdf': kdf,
                'datahash': digest.hex(),
                'signature': sig.hex(),
            })
    return rows


# Built at import time so the JSONL payload is ready for the test
# without re-signing on every invocation.
VERIFY_SIG_ROWS = _build_verify_sig_rows()


def _build_verify_sig_payload() -> str:
    return '\n'.join(json.dumps(row) for row in VERIFY_SIG_ROWS) + '\n'


# ---------------------------------------------------------------------------
# The test itself. Skipped if the Rust binary is missing (CI without a
# yubtc-xcompat checkout); otherwise runs the full table.
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not _kat_check_available(),
    reason=f'Rust harness not found at {_kat_check_bin()!r} '
           '(set KAT_CHECK_BIN to override)',
)
def test_python_seed2bin_kat_matches_rust():
    """For every (seed, nonce, passphrase, kdf) row, Rust's seed2bin
    must reproduce Python's expected output bit-for-bit.

    A failure here means one of the two implementations has drifted:
    the MISMATCH line in stderr names the kdf and nonce so the
    offending primitive is easy to find.
    """
    payload = _build_payload()
    proc = subprocess.run(
        [_kat_check_bin()],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f'kat_check exited {proc.returncode} -- divergence detected.\n'
        f'stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
    )
    # The Rust harness prints a single OK line with the vector count.
    assert '[kat_check] OK' in proc.stdout


@pytest.mark.skipif(
    not _kat_check_available(),
    reason=f'Rust harness not found at {_kat_check_bin()!r} '
           '(set KAT_CHECK_BIN to override)',
)
def test_kat_check_payload_covers_every_kdf_and_nonce():
    """Sanity: the JSONL payload exercises all four KDFs at three nonces.

    A test that accidentally drops a KDF or a nonce silently weakens
    the fence -- this test catches that regression.
    """
    seen = {(row['kdf'], row['nonce']) for row in KAT_ROWS}
    expected = {
        ('yubtc', 0), ('yubtc', 1), ('yubtc', 7),
        ('pbkdf2', 0), ('pbkdf2', 1), ('pbkdf2', 7),
        ('argon2id', 0), ('argon2id', 1), ('argon2id', 7),
        ('scrypt', 0), ('scrypt', 1), ('scrypt', 7),
    }
    # yubtc is only exercised with non-empty passphrase via the
    # pbkdf2/argon2id/scrypt rows; that's fine -- a yubtc-with-pass
    # row would raise and the harness would report FAIL, so the
    # coverage assertion stays tight.
    assert seen == expected
    # Total row count stays at the same value as the seed2bin KAT
    # table pinned in test_crypto.py (21 vectors: 3 yubtc + 9 pbkdf2 +
    # 9 argon2id + 9 scrypt with valid (kdf, passphrase) combos --
    # but yubtc+non-empty would raise, so the cross-compat payload is
    # 3 + 6 + 6 + 6 = 21; matches the KAT count in test_crypto.py).
    assert len(KAT_ROWS) == 21


@pytest.mark.skipif(
    not _kat_check_available(),
    reason=f'Rust harness not found at {_kat_check_bin()!r} '
           '(set KAT_CHECK_BIN to override)',
)
def test_python_verify_sig_kat_matches_rust():
    """For every (signing primitive, kdf, nonce) row, Rust's
    VerifyingKey must accept the Python signature under the same
    digest.

    Two signing primitives are exercised here:

    - **`sign_hash`** — Python signs `VERIFY_SIG_DATAHASH` directly.
      The harness verifies against `VERIFY_SIG_DATAHASH`. A bug that
      pre-hashed the input (e.g. `sign(sha256(datahash))`) would
      produce a signature over `sha256(datahash)`, which the
      harness refuses.

    - **`sign_data`** — Python signs `VERIFY_SIG_RAW_DATA`; the
      harness verifies against `sha256(sha256(VERIFY_SIG_RAW_DATA))`
      (Bitcoin's transaction-hash convention). A bug that inserted
      an extra SHA-256 layer (e.g. signing `sha256(sha256(sha256(
      sha256(data))))`) would produce a signature over the
      wrong digest, and the harness refuses.

    A failure here means Python's signing primitive has drifted
    from the Bitcoin convention; the SIGNATURE INVALID line in
    stderr names the kdf and nonce.
    """
    payload = _build_verify_sig_payload()
    proc = subprocess.run(
        [_kat_check_bin()],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f'kat_check exited {proc.returncode} -- divergence detected.\n'
        f'stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
    )
    assert '[kat_check] OK' in proc.stdout


@pytest.mark.skipif(
    not _kat_check_available(),
    reason=f'Rust harness not found at {_kat_check_bin()!r} '
           '(set KAT_CHECK_BIN to override)',
)
def test_verify_sig_payload_covers_every_kdf_and_nonce_and_primitive():
    """Sanity: the verify_sig JSONL payload exercises all four KDFs at
    three nonces, with both `sign_hash` and `sign_data` rows.

    A test that drops a KDF, a nonce, or a signing primitive silently
    weakens the fence -- this test catches that regression by
    asserting the cross-product stays full.
    """
    seen = {(row['kdf'], row['nonce']) for row in VERIFY_SIG_ROWS}
    expected = {
        ('yubtc', 0), ('yubtc', 1), ('yubtc', 7),
        ('pbkdf2', 0), ('pbkdf2', 1), ('pbkdf2', 7),
        ('argon2id', 0), ('argon2id', 1), ('argon2id', 7),
        ('scrypt', 0), ('scrypt', 1), ('scrypt', 7),
    }
    assert seen == expected
    # 4 KDFs × 3 nonces × 2 signing primitives = 24 vectors. Anything
    # less means the test is no longer exercising the full cross-
    # product, so a regression in one primitive would slip through.
    assert len(VERIFY_SIG_ROWS) == 24
