import pytest


# The canonical 12-word BIP-39 test mnemonic; the same phrase the Rust
# core's kdf tests use ("abandon ".repeat(11).trim() + " about").
_M12_SEED = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'


@pytest.mark.parametrize('seed, privhex, privwif, address',
                         [('qwe',
                           '1814825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0455',
                           b'Kx2X5mom9zTGkQq38v8swx3z5ApAuRnwq4wfyF52Y55v6Ke5dRq5',
                           b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'),
                          ('12345',
                           '28820488de48082a13c570e68e1295e0207c6ef826a685c220d10fd6d8b95d49',
                           b'KxaTDqped9KdUsW3KhAyF6KkLWktFvsNo7yvmBke7U62tWmMs8dk',
                           b'1sW6JDNWppzUjQr8jjQ9KJmVx92ooKEd6'),
                          ])
def test(seed, privhex, privwif, address):
    from yubtc.crypto import seed2privkey, privkey2privwif, privkey2addr
    privkey = seed2privkey(seed=seed, nonce=0, passphrase='')
    assert privkey.secret.hex() == privhex
    assert privkey2privwif(privkey=privkey) == privwif
    assert privkey2addr(privkey=privkey) == address


"""
this test included in main test()
def test_bin2privkey():
    import axolotl_curve25519 as curve
    from yubtc.crypto import seed2privkey, seed2bin
    seed = 'my test seed'
    assert seed2privkey(seed, passphrase='') == curve.generatePrivateKey(seed2bin(seed, passphrase=''))
"""


# ---------------------------------------------------------------------------
# seed2bin: the KDF. Output is 32 bytes; deterministic in seed and nonce.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('seed, nonce, expected', [
    ('qwe', 0, '1c14825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0455'),
    ('12345', 0, '2d820488de48082a13c570e68e1295e0207c6ef826a685c220d10fd6d8b95d89'),
    ('', 0, '07407db254d500c0b614d835abe6a525a80eada073a8f67e6350cd18678e8cf6'),
    ('qwe', 7, '1f2b3272b320b5be8dae398655d2e25924a9ba9676b78b9eb095691fcb2c8c23'),
])
def test_seed2bin_known_answers(seed, nonce, expected):
    from yubtc.crypto import seed2bin
    out = seed2bin(seed=seed, nonce=nonce, passphrase='')
    assert len(out) == 32
    assert out.hex() == expected


def test_seed2bin_nonce_changes_output():
    """The nonce is meant to derive distinct addresses from one seed."""
    from yubtc.crypto import seed2bin
    assert seed2bin(seed='qwe', nonce=0, passphrase='') != seed2bin(seed='qwe', nonce=1, passphrase='')
    assert seed2bin(seed='qwe', nonce=0, passphrase='') != seed2bin(seed='qwe', nonce=7, passphrase='')


def test_seed2bin_raises_when_nonce_missing():
    """nonce is required -- callers must pass it explicitly."""
    from yubtc.crypto import seed2bin
    with pytest.raises(TypeError, match='nonce not set'):
        seed2bin(seed='qwe', passphrase='')


# ---------------------------------------------------------------------------
# seed2bin with passphrase: the optional 25th-word extension.
#
# The empty-passphrase path must stay bit-for-bit identical to the
# no-passphrase call so a wallet that's been around since before
# passphrase support can still open. A non-empty passphrase routes the
# seed through PBKDF2-HMAC-SHA512 (2048 iters) before the cascade, so
# a different passphrase always yields a different key.
# ---------------------------------------------------------------------------


def test_seed2bin_empty_passphrase_matches_no_passphrase():
    """The default of `passphrase=''` is the legacy KDF path -- the
    output is identical to the pre-passphrase code."""
    from yubtc.crypto import seed2bin
    for seed, nonce in [('qwe', 0), ('qwe', 7), ('12345', 0),
                        ('a much longer seed phrase here', 3)]:
        assert seed2bin(seed=seed, nonce=nonce, passphrase='') == \
            seed2bin(seed=seed, nonce=nonce, passphrase='')


@pytest.mark.parametrize('seed, nonce, passphrase, expected', [
    # Locked to the BIP-32/BIP-44 path: PBKDF2(mnemonic, "mnemonic"+pass,
    # 2048 iters, 64B) → master → m/44'/0'/0'/0/<nonce>. Any change to
    # the KDF would break the KAT and surface here.
    ('qwe', 0, 'hunter2', '0ed52a08de77f0bcdebe34ed43c1716e95bdc31047289a49d973118ae625cba4'),
    ('qwe', 0, 'test-pass', '634900eb40be06a7525f06c2d419d74e26230b4d4de02aa3f17f8831f549866a'),
    ('qwe', 7, 'hunter2', '3467e5fee5e5bac0638595da13772d33a1be049612d7b68ee0a05222051f6c64'),
])
def test_seed2bin_passphrase_known_answers(seed, nonce, passphrase, expected):
    from yubtc.crypto import seed2bin
    out = seed2bin(seed=seed, nonce=nonce, passphrase=passphrase)
    assert len(out) == 32
    assert out.hex() == expected


def test_seed2bin_passphrase_changes_output():
    """A non-empty passphrase must produce a different key than the
    empty path -- otherwise the parameter is silently ignored."""
    from yubtc.crypto import seed2bin
    empty = seed2bin(seed='qwe', nonce=0, passphrase='')
    with_pw = seed2bin(seed='qwe', nonce=0, passphrase='hunter2')
    assert empty != with_pw


def test_seed2bin_passphrase_is_sensitive_to_value():
    """Two different non-empty passphrases must derive distinct keys."""
    from yubtc.crypto import seed2bin
    a = seed2bin(seed='qwe', nonce=0, passphrase='alpha')
    b = seed2bin(seed='qwe', nonce=0, passphrase='beta')
    assert a != b


# ---------------------------------------------------------------------------
# seed2bin(kdf=...): all four KDF algorithms (the Phase 0+ backport).
#
# Mirrors yubtc core/src/kdf.rs::seed2bin. Every expected hex constant
# below is a KAT verified bit-for-bit against the Rust core: the vectors
# were derived with this module and re-verified by the Rust cross-compat
# harness (`cargo build -p yubtc-core --example kat_check`, then the
# JSONL vector lines piped through stdin; exit code 0 means the Rust
# core reproduced the same bytes for every vector).
# ---------------------------------------------------------------------------


def test_default_kdf_matches_rust():
    """`KdfAlgo::default_for`: empty passphrase -> 'yubtc', non-empty
    -> 'pbkdf2'."""
    from yubtc.crypto import default_kdf
    assert default_kdf(passphrase='') == 'yubtc'
    assert default_kdf(passphrase='hunter2') == 'pbkdf2'


def test_kdf_error_hierarchy():
    """The typed KDF errors mirror the Rust `KdfError` variants and all
    share the `ValueError` base so generic "bad KDF input" handlers work."""
    from yubtc.crypto import (
        Bip32Error, EmptyPassphraseIncompatible, KdfError, PassphraseRequired,
    )
    assert issubclass(KdfError, ValueError)
    for variant in (PassphraseRequired, EmptyPassphraseIncompatible, Bip32Error):
        assert issubclass(variant, KdfError)


@pytest.mark.parametrize('seed, nonce, passphrase, kdf, expected', [
    # Legacy cascade, empty passphrase: identical bytes to the
    # pre-passphrase wallets (see the KAT above: same vector family).
    (_M12_SEED, 0, '', 'yubtc',
     'e47a0307ca0c0415fea1fdf37816950f7b337a9f1822313770c76d102180a548'),
    # BIP-39-compatible pbkdf2.
    (_M12_SEED, 0, 'test', 'pbkdf2',
     '8f444af967d53a26ae807f06c4f85702478b0b227b1070bd989c8ca6a29b853b'),
    (_M12_SEED, 7, 'hunter2', 'pbkdf2',
     'fa12b7ba0c1b4a1b462ecda99f86c965eff85aec256d1229cabee3edcde97b71'),
    # pbkdf2 NFKD pin: the passphrase is NFKD-normalised, so the
    # decomposed form (e + combining acute, 'e\u0301') lands on the
    # same key as the composed one ('\u00e9'). Rust verified the same
    # bytes for both rows.
    (_M12_SEED, 0, 'é', 'pbkdf2',
     '3c88f652acc3eb3e32f5cc5444d4b2c565919f69d810d9f397099c99a0c2c79e'),
    (_M12_SEED, 0, 'e\u0301', 'pbkdf2',
     '3c88f652acc3eb3e32f5cc5444d4b2c565919f69d810d9f397099c99a0c2c79e'),
    # Argon2id: m=64 MiB, t=3, p=4, salt tag 'yubtc-argon2id-v1\0'.
    (_M12_SEED, 0, 'test', 'argon2id',
     '23ccae646483b73b670cfaf5e747ce7f72ca590a446c13e103145c0348d4365c'),
    # Argon2id raw-bytes pin: NO NFKD here -- the decomposed passphrase
    # hashes different bytes and therefore a different key than the
    # composed one. Rust verified the same bytes.
    (_M12_SEED, 0, 'e\u0301', 'argon2id',
     '442f638bc7b108e7f0db8b8c3e94d1fea508d407f062c4ff806f26382819f271'),
    # scrypt: N=2^15, r=16 (64 MiB), p=1, salt tag 'yubtc-scrypt-v2\0'.
    (_M12_SEED, 0, 'test', 'scrypt',
     'b55a8c1fa10704a68bd1182e094d4615f4669a0c1db02022770875547b3015df'),
])
def test_seed2bin_kdf_known_answers(seed, nonce, passphrase, kdf, expected):
    from yubtc.crypto import seed2bin
    out = seed2bin(seed=seed, nonce=nonce, passphrase=passphrase, kdf=kdf)
    assert len(out) == 32
    assert out.hex() == expected


def test_seed2bin_explicit_yubtc_kdf_matches_legacy_vector():
    """Passing kdf='yubtc' explicitly reproduces the pre-existing
    legacy KAT -- the parameter did not move the legacy bytes."""
    from yubtc.crypto import seed2bin
    assert seed2bin(seed='qwe', nonce=0, passphrase='', kdf='yubtc').hex() == \
        '1c14825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0455'
    assert seed2bin(seed='qwe', nonce=7, passphrase='', kdf='yubtc').hex() == \
        '1f2b3272b320b5be8dae398655d2e25924a9ba9676b78b9eb095691fcb2c8c23'


@pytest.mark.parametrize('nonce, passphrase, kdf', [
    (0, '', 'yubtc'),
    (7, '', 'yubtc'),
    (0, 'hunter2', 'pbkdf2'),
])
def test_seed2bin_without_kdf_matches_explicit_default(nonce, passphrase, kdf):
    """Omitting `kdf` keeps the historic routing (empty passphrase ->
    yubtc, non-empty -> pbkdf2): same bytes as the explicit choice."""
    from yubtc.crypto import default_kdf, seed2bin
    assert seed2bin(seed='qwe', nonce=nonce, passphrase=passphrase) == \
        seed2bin(seed='qwe', nonce=nonce, passphrase=passphrase,
                 kdf=default_kdf(passphrase=passphrase))


def test_seed2bin_yubtc_kdf_rejects_passphrase():
    """The legacy cascade is passphrase-free by definition (mirrors
    `KdfError::EmptyPassphraseIncompatible`)."""
    from yubtc.crypto import EmptyPassphraseIncompatible, seed2bin
    with pytest.raises(EmptyPassphraseIncompatible,
                       match='empty passphrase is incompatible with kdf=yubtc'):
        seed2bin(seed='qwe', nonce=0, passphrase='x', kdf='yubtc')


@pytest.mark.parametrize('kdf', ['pbkdf2', 'argon2id', 'scrypt'])
def test_seed2bin_passphrase_kdfs_reject_empty_passphrase(kdf):
    """The stretch needs a passphrase (mirrors `KdfError::PassphraseRequired`)."""
    from yubtc.crypto import PassphraseRequired, seed2bin
    with pytest.raises(PassphraseRequired, match=f'passphrase required for kdf={kdf}'):
        seed2bin(seed='qwe', nonce=0, passphrase='', kdf=kdf)


def test_seed2bin_unknown_kdf_raises():
    from yubtc.crypto import seed2bin
    with pytest.raises(ValueError, match="unknown kdf: 'sha3'"):
        seed2bin(seed='qwe', nonce=0, passphrase='x', kdf='sha3')


def test_seed2bin_rejects_kdf_none():
    """An explicit `None` is not a KDF choice -- the wrapper rejects it
    the same way it does for every other non-None-default parameter."""
    from yubtc.crypto import seed2bin
    with pytest.raises(ValueError, match='kdf is None'):
        seed2bin(seed='qwe', nonce=0, passphrase='x', kdf=None)


@pytest.mark.parametrize('kdf', ['yubtc', 'pbkdf2', 'argon2id', 'scrypt'])
def test_seed2bin_kdf_separates_nonces(kdf):
    """Regression guard (mirrors the Rust `every_kdf_separates_nonces`):
    every KDF must derive distinct keys for distinct nonces -- one key
    per nonce is what keeps the wallet from silently reusing an address."""
    from yubtc.crypto import seed2bin
    passphrase = '' if kdf == 'yubtc' else 'test'
    outs = {seed2bin(seed=_M12_SEED, nonce=n, passphrase=passphrase, kdf=kdf)
            for n in (0, 1, 999)}
    assert len(outs) == 3


@pytest.mark.parametrize('kdf', ['pbkdf2', 'argon2id', 'scrypt'])
def test_seed2bin_kdf_is_sensitive_to_passphrase_value(kdf):
    from yubtc.crypto import seed2bin
    a = seed2bin(seed='qwe', nonce=0, passphrase='alpha', kdf=kdf)
    b = seed2bin(seed='qwe', nonce=0, passphrase='beta', kdf=kdf)
    assert a != b


def test_seed2bin_rejects_nonce_at_hardened_flag():
    """BIP-32 caps non-hardened child indexes at 2^31 (mirrors
    `KdfError::Bip32` via `make_bip44_path`). The check lives in the
    shared `_bip44_leaf`, so one KDF exercises it for all three."""
    from yubtc.crypto import Bip32Error, seed2bin
    with pytest.raises(Bip32Error, match='BIP-32 derivation failed'):
        seed2bin(seed=_M12_SEED, nonce=0x80000000, passphrase='test', kdf='pbkdf2')


def test_seed2privkey_explicit_yubtc_kdf_keeps_clamp():
    """Decision C1: kdf='yubtc' is the clamped branch, exactly like the
    omitted-kdf default with an empty passphrase."""
    from yubtc.crypto import bin2privkey, seed2bin, seed2privkey
    raw = seed2bin(seed='qwe', nonce=0, passphrase='', kdf='yubtc')
    key = seed2privkey(seed='qwe', nonce=0, passphrase='', kdf='yubtc')
    assert key.secret == bin2privkey(raw)


@pytest.mark.parametrize('kdf', ['pbkdf2', 'argon2id', 'scrypt'])
def test_seed2privkey_bip44_kdfs_skip_clamp(kdf):
    """Decision C1: the BIP-44-leaf KDFs feed the raw leaf to
    secp256k1 verbatim -- no clamp -- so addresses match what
    Trezor/Ledger/Electrum derive for the same (mnemonic, passphrase)."""
    from yubtc.crypto import bin2privkey, seed2bin, seed2privkey
    raw = seed2bin(seed=_M12_SEED, nonce=0, passphrase='test', kdf=kdf)
    key = seed2privkey(seed=_M12_SEED, nonce=0, passphrase='test', kdf=kdf)
    assert key.secret == raw
    assert key.secret != bin2privkey(raw)


@pytest.mark.parametrize('nonce, passphrase', [(0, ''), (0, 'hunter2')])
def test_seed2privkey_without_kdf_matches_explicit_default(nonce, passphrase):
    """Omitting `kdf` in seed2privkey keeps the historic routing and
    clamp policy: same key as passing `default_kdf(passphrase)`."""
    from yubtc.crypto import default_kdf, seed2privkey
    auto = seed2privkey(seed='qwe', nonce=nonce, passphrase=passphrase)
    explicit = seed2privkey(seed='qwe', nonce=nonce, passphrase=passphrase,
                            kdf=default_kdf(passphrase=passphrase))
    assert auto.secret == explicit.secret


def test_seed2privkey_raises_when_nonce_missing():
    """seed2privkey's nonce is also required."""
    from yubtc.crypto import seed2privkey
    with pytest.raises(TypeError, match='nonce not set'):
        seed2privkey(seed='qwe', passphrase='')


def test_seed2privkey_passphrase_changes_privkey():
    """End-to-end: a passphrase change must produce a different PrivateKey."""
    from yubtc.crypto import seed2privkey
    a = seed2privkey(seed='qwe', nonce=0, passphrase='')
    b = seed2privkey(seed='qwe', nonce=0, passphrase='hunter2')
    assert a != b


def test_seed2privkey_empty_passphrase_keeps_clamp():
    """Decision C1: the legacy cascade branch (empty passphrase) still
    clamps, bit-for-bit with pre-passphrase yubtc wallets."""
    from yubtc.crypto import bin2privkey, seed2bin, seed2privkey
    raw = seed2bin(seed='qwe', nonce=0, passphrase='')
    key = seed2privkey(seed='qwe', nonce=0, passphrase='')
    assert key.secret == bin2privkey(raw)


def test_seed2privkey_passphrase_skips_clamp():
    """Decision C1: the BIP-39 branch (non-empty passphrase) feeds the
    raw 32-byte BIP-44 leaf to secp256k1 verbatim — no clamp — so
    addresses match Trezor/Ledger/Electrum for the same
    (mnemonic, passphrase). Mirrors the Rust port."""
    from yubtc.crypto import bin2privkey, seed2bin, seed2privkey
    raw = seed2bin(seed='qwe', nonce=0, passphrase='hunter2')
    key = seed2privkey(seed='qwe', nonce=0, passphrase='hunter2')
    assert key.secret == raw
    assert key.secret != bin2privkey(raw)


# ---------------------------------------------------------------------------
# bin2privkey: clamps a 32-byte seed into a valid secp256k1 scalar.
#
# The rules live in crypto.py:31-40. The `|= 64` form (commit c7fa3b8)
# replaced `+= 64` -- the older form overflowed into bit 7 when the input
# already had bit 6 set, producing a corrupted key that still *looked* valid.
# These vectors lock the behaviour each one pins.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('raw, expected', [
    # All zeros -> only the OR rule fires; bit 6 of byte 31 is set.
    (b'\x00' * 32, '0000000000000000000000000000000000000000000000000000000000000040'),
    # All ones -> bits 0-2 of byte 0 are zeroed; bit 7 of byte 31 is cleared
    # (this is the case that distinguishes |= 64 from += 64 -- the byte
    # would end up 0xbf instead of 0x7f under the old code).
    (b'\xff' * 32, 'f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
    # Alternating nibbles -> byte 0 drops 0x05 -> 0x00 (low three bits zeroed);
    # byte 31's 0xA5 becomes 0x25 & 0x7F | 0x40 = 0x65.
    (b'\xa5' * 32, 'a0a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a565'),
])
def test_bin2privkey_clamps_per_spec(raw, expected):
    from yubtc.crypto import bin2privkey
    out = bin2privkey(raw)
    assert len(out) == 32
    assert out.hex() == expected


def test_bin2privkey_preserves_middle_bits():
    """Bytes 1..30 are untouched -- only byte 0 and byte 31 are clamped."""
    from yubtc.crypto import bin2privkey
    raw = bytes([0x07]) * 1 + bytes(range(1, 31)) + bytes([0xC0])
    out = bin2privkey(raw)
    # Byte 0: 0x07 & 0xF8 = 0x00
    assert out[0] == 0x00
    # Bytes 1..30 copied through untouched
    assert out[1:31] == raw[1:31]
    # Byte 31: 0xC0 & 0x7F | 0x40 = 0x40 (bit 6 already set, bit 7 cleared)
    assert out[31] == 0x40


# ---------------------------------------------------------------------------
# seed2privkey: seed2bin composed with bin2privkey. The pre-clamp seed2bin
# output is the *unclamped* seed; the post-clamp output is the privkey.
# ---------------------------------------------------------------------------

def test_seed2privkey_equals_clamp_of_seed2bin():
    from coincurve import PrivateKey
    from yubtc.crypto import seed2bin, bin2privkey, seed2privkey
    for seed in ('qwe', '12345', 'a much longer seed phrase here'):
        kw = {'seed': seed, 'nonce': 0, 'passphrase': ''}
        assert seed2privkey(**kw) == PrivateKey(bin2privkey(seed2bin(**kw)))


def test_seed2privkey_nonce_changes_privkey():
    from yubtc.crypto import seed2privkey
    a = seed2privkey(seed='qwe', nonce=0, passphrase='')
    b = seed2privkey(seed='qwe', nonce=1, passphrase='')
    assert a != b


# ---------------------------------------------------------------------------
# privkey2privwif / privwif2privkey: round-trip plus contract checks.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('privkey', [
    # secp256k1 scalar range: 1 <= x < n. Edge cases at the boundary.
    # n - 1: largest valid scalar.
    (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140).to_bytes(32, 'big'),
    # n / 2: middle of the order.
    (0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0).to_bytes(32, 'big'),
    # the canonical "qwe" seed test vector.
    bytes.fromhex('1814825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0455'),
])
def test_privwif_roundtrip(privkey):
    from coincurve import PrivateKey
    from yubtc.crypto import privkey2privwif, privwif2privkey
    wif = privkey2privwif(privkey=PrivateKey(privkey))
    assert privwif2privkey(wif) == PrivateKey(privkey)


def test_privwif2privkey_rejects_uncompressed_wif():
    """Only the compressed form (33 bytes with 0x01 suffix) is accepted."""
    from yubtc.base58check import base58CheckEncode
    from yubtc.crypto import PREFIX_PRIVKEY, privwif2privkey
    # Hand-roll an uncompressed WIF: PREFIX_PRIVKEY || secret (no 0x01 suffix).
    uncompressed_wif = base58CheckEncode(
        bytes([PREFIX_PRIVKEY]) + b'\x11' * 32,
    )
    with pytest.raises(ValueError, match='uncompressed wif not supported'):
        privwif2privkey(uncompressed_wif)


def test_privwif2privkey_rejects_bad_prefix():
    from yubtc.crypto import privwif2privkey, PREFIX_P2PKH
    from yubtc.base58check import base58CheckEncode
    not_a_privkey = base58CheckEncode(bytes([PREFIX_P2PKH]) + b'\x00' * 20)
    with pytest.raises(ValueError, match='prefix mismatch'):
        privwif2privkey(not_a_privkey)


# ---------------------------------------------------------------------------
# privkey2pubkey / pubkey2addr: 33-byte compressed pubkey -> P2PKH address.
# ---------------------------------------------------------------------------

def test_privkey2pubkey_length_and_determinism():
    """The pubkey is 33 bytes (compressed) and deterministic."""
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey(seed='qwe', nonce=0, passphrase='')
    a = privkey2pubkey(privkey=privkey)
    b = privkey2pubkey(privkey=privkey)
    assert len(a) == 33
    assert a == b


def test_privkey2pubkey_known_answer():
    from yubtc.crypto import seed2privkey, privkey2pubkey
    expected = '03eff5d63eedb62d21b86780b468e5ca9c2f938be2f0b23c05cd76ae1508a178d0'
    assert privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0, passphrase='')).hex() == expected


def test_privkey2pubkey_prefix_signals_y_parity():
    """The leading byte is 0x02 or 0x03 depending on the parity of y."""
    from yubtc.crypto import seed2privkey, privkey2pubkey, PREFIX_PUBKEY
    pubkey = privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    assert pubkey[0] in (PREFIX_PUBKEY, PREFIX_PUBKEY | 1)


# ---------------------------------------------------------------------------
# sign_hash / sign_data: ECDSA signatures on secp256k1.
#
# The DER-encoded signature is random per call (the ecdsa library uses a
# fresh k -- `sigencode_der_canonize` only enforces low-s, not RFC 6979
# determinism). The pinning test is therefore *recovery*, not the bytes.
# ---------------------------------------------------------------------------

def test_sign_hash_is_der_canonical_low_s():
    """Every signature is DER-encoded, and the s component is in the lower half of the order."""
    from yubtc.crypto import seed2privkey, sign_hash
    privkey = seed2privkey(seed='qwe', nonce=0, passphrase='')
    digest = b'\x42' * 32
    for _ in range(3):
        sig = sign_hash(privkey=privkey, datahash=digest)
        # DER structure: 0x30 [len] 0x02 [r-len] r 0x02 [s-len] s
        assert sig[0] == 0x30
        r_len = sig[3]
        assert sig[2] == 0x02
        assert sig[4 + r_len] == 0x02
        s_len = sig[5 + r_len]
        s = int.from_bytes(sig[6 + r_len:6 + r_len + s_len], 'big')
        # low-s: s must be <= n/2. n is the secp256k1 group order.
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        assert s <= n // 2


def test_sign_hash_verifies():
    from yubtc.crypto import seed2privkey, sign_hash
    privkey = seed2privkey(seed='qwe', nonce=0, passphrase='')
    digest = b'\x42' * 32
    sig = sign_hash(privkey=privkey, datahash=digest)
    assert privkey.public_key.verify(sig, digest, hasher=None)


def test_sign_data_verifies():
    """sign_data(data) signs sha256(sha256(data)) and produces a valid DER signature."""
    from yubtc.crypto import seed2privkey, sign_data
    from yubtc.hash import sha256
    privkey = seed2privkey(seed='qwe', nonce=0, passphrase='')
    sig = sign_data(privkey=privkey, data=b'abc')
    assert privkey.public_key.verify(sig, sha256(sha256(b'abc')), hasher=None)


# ---------------------------------------------------------------------------
# make_lock_script: the scriptPubKey for a destination.
#
# P2PKH (prefix 0x00) and P2SH (prefix 0x05) are the two address families
# this wallet handles. The dsthash argument is the 20-byte hash *after*
# the prefix -- for P2SH it is the script hash of the redeem script.
# ---------------------------------------------------------------------------

def test_make_lock_script_p2pkh():
    """A P2PKH address produces the standard OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG."""
    from yubtc.crypto import make_lock_script, seed2privkey, privkey2addr
    addr = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    # OP_DUP(0x76) OP_HASH160(0xa9) <20B> OP_EQUALVERIFY(0x88) OP_CHECKSIG(0xac)
    assert make_lock_script(addr).hex() == '76a914e96b5b4561e70170c16f51ca30a9429e3bede97788ac'


def test_make_lock_script_p2sh():
    """A P2SH address produces OP_HASH160 <20B> OP_EQUAL — the dsthash IS the script hash."""
    from yubtc.crypto import make_lock_script
    from yubtc.base58check import base58CheckEncode
    from yubtc.crypto import PREFIX_P2SH
    script_hash = b'\xab' * 20
    addr = base58CheckEncode(bytes([PREFIX_P2SH]) + script_hash)
    # OP_HASH160(0xa9) <20B> OP_EQUAL(0x87)
    assert make_lock_script(addr).hex() == 'a914' + script_hash.hex() + '87'


def test_make_lock_script_unknown_prefix_raises():
    from yubtc.crypto import make_lock_script
    from yubtc.base58check import base58CheckEncode
    from yubtc.crypto import PREFIX_TESTNET_P2PKH
    unknown = base58CheckEncode(bytes([PREFIX_TESTNET_P2PKH]) + b'\x00' * 20)
    with pytest.raises(ValueError, match='address not supported'):
        make_lock_script(unknown)


# ---------------------------------------------------------------------------
# make_vout: builds the list of transaction outputs for a spend.
#
# Three branches: (1) amount is None or amount+fee == in_amount -- drain the
# input, no change; (2) anything else -- send `amount` and route the rest
# back to `src`. The cashback return value is the change amount (0 for
# branch 1).
# ---------------------------------------------------------------------------

def test_make_vout_drains_when_amount_is_none():
    """`amount=None` means "send everything available"."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    dst = privkey2addr(privkey=seed2privkey(seed='asdf', nonce=0, passphrase=''))
    result = make_vout(src=src, dst=dst, in_amount=100_000, amount=None, fee=1_000)
    assert result.cashback == 0
    assert result.amount == 99_000
    assert len(result.vout) == 1
    assert result.vout[0].amount == 99_000
    # The single output locks the destination, not the source.
    assert result.vout[0].script.hex() == '76a914d9d50a8ac051c555bf9a514aee0e4835efb3273888ac'


def test_make_vout_drains_when_amount_plus_fee_equals_input():
    """`amount + fee == in_amount` is the explicit form of "send everything"."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    dst = privkey2addr(privkey=seed2privkey(seed='asdf', nonce=0, passphrase=''))
    result = make_vout(src=src, dst=dst, in_amount=100_000, amount=99_000, fee=1_000)
    assert result.cashback == 0
    assert result.amount == 99_000
    assert len(result.vout) == 1 and result.vout[0].amount == 99_000


def test_make_vout_sends_change_back_to_src():
    """Anything left over after amount+fee is routed back to the source address."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    dst = privkey2addr(privkey=seed2privkey(seed='asdf', nonce=0, passphrase=''))
    result = make_vout(src=src, dst=dst, in_amount=100_000, amount=40_000, fee=1_000)
    assert result.cashback == 59_000
    assert result.amount == 40_000
    assert len(result.vout) == 2
    # Output order: [change (back to src), payment (to dst)].
    assert result.vout[0].amount == 59_000
    assert result.vout[0].script.hex() == '76a914e96b5b4561e70170c16f51ca30a9429e3bede97788ac'
    assert result.vout[1].amount == 40_000
    assert result.vout[1].script.hex() == '76a914d9d50a8ac051c555bf9a514aee0e4835efb3273888ac'


def test_make_vout_drain_raises_when_input_does_not_cover_fee():
    """amount=None with in_amount < fee: the drain would go negative."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    dst = privkey2addr(privkey=seed2privkey(seed='asdf', nonce=0, passphrase=''))
    with pytest.raises(ValueError, match='input does not cover fee'):
        make_vout(src=src, dst=dst, in_amount=500, amount=None, fee=1_000)


def test_make_vout_drain_raises_when_input_equals_fee():
    """amount=None with in_amount == fee: still valid (sends 0 to dst)."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    dst = privkey2addr(privkey=seed2privkey(seed='asdf', nonce=0, passphrase=''))
    result = make_vout(src=src, dst=dst, in_amount=1_000, amount=None, fee=1_000)
    assert result.amount == 0
    assert result.cashback == 0
    assert result.vout[0].amount == 0


def test_make_vout_raises_when_amount_plus_fee_exceeds_input():
    """Non-drain: amount + fee > in_amount would produce a negative cashback."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    dst = privkey2addr(privkey=seed2privkey(seed='asdf', nonce=0, passphrase=''))
    with pytest.raises(ValueError, match=r'amount \+ fee exceeds input'):
        make_vout(src=src, dst=dst, in_amount=10_000, amount=50_000, fee=1_000)


def test_make_vout_exact_no_change_does_not_trip_drain_check():
    """amount + fee == in_amount is the "exact spend" branch -- no error."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    dst = privkey2addr(privkey=seed2privkey(seed='asdf', nonce=0, passphrase=''))
    result = make_vout(src=src, dst=dst, in_amount=11_000, amount=10_000, fee=1_000)
    assert result.cashback == 0
    assert result.amount == 10_000


def test_seed2bin_raises_when_seed_missing():
    """seed is required -- callers must pass it explicitly."""
    from yubtc.crypto import seed2bin
    with pytest.raises(TypeError, match='seed not set'):
        seed2bin(nonce=0, passphrase='')


def test_seed2privkey_raises_when_seed_missing():
    """seed2privkey's seed is also required."""
    from yubtc.crypto import seed2privkey
    with pytest.raises(TypeError, match='seed not set'):
        seed2privkey(nonce=0, passphrase='')


def test_privwif_raises_when_privkey_missing():
    """privkey2privwif's `privkey` is required -- callers must pass it."""
    from yubtc.crypto import privkey2privwif
    with pytest.raises(TypeError, match='privkey not set'):
        privkey2privwif()


def test_privkey2addr_raises_when_privkey_missing():
    """privkey2addr's `privkey` is required -- callers must pass it."""
    from yubtc.crypto import privkey2addr
    with pytest.raises(TypeError, match='privkey not set'):
        privkey2addr()


def test_pubkey2addr_raises_when_pubkey_missing():
    """pubkey2addr's `pubkey` is required -- callers must pass it."""
    from yubtc.crypto import pubkey2addr
    with pytest.raises(TypeError, match='pubkey not set'):
        pubkey2addr()


def test_sign_hash_raises_when_privkey_missing():
    from yubtc.crypto import sign_hash
    with pytest.raises(TypeError, match='privkey not set'):
        sign_hash(datahash=b'\x42' * 32)


def test_sign_hash_raises_when_datahash_missing():
    from yubtc.crypto import seed2privkey, sign_hash
    privkey = seed2privkey(seed='qwe', nonce=0, passphrase='')
    with pytest.raises(TypeError, match='datahash not set'):
        sign_hash(privkey=privkey)


def test_sign_data_raises_when_privkey_missing():
    from yubtc.crypto import sign_data
    with pytest.raises(TypeError, match='privkey not set'):
        sign_data(data=b'abc')


def test_sign_data_raises_when_data_missing():
    from yubtc.crypto import seed2privkey, sign_data
    privkey = seed2privkey(seed='qwe', nonce=0, passphrase='')
    with pytest.raises(TypeError, match='data not set'):
        sign_data(privkey=privkey)


def test_make_vout_raises_when_required_kwarg_missing():
    from yubtc.crypto import make_vout
    # Each required kwarg is omitted in turn; an explicit `None` is a
    # valid value (drain sentinel) and must NOT trigger this guard.
    base = dict(src=b'\x00' * 20, dst=b'\x00' * 20, in_amount=100_000, amount=None, fee=1_000)
    with pytest.raises(TypeError, match='src not set'):
        make_vout(**{k: v for k, v in base.items() if k != 'src'})
    with pytest.raises(TypeError, match='dst not set'):
        make_vout(**{k: v for k, v in base.items() if k != 'dst'})
    with pytest.raises(TypeError, match='in_amount not set'):
        make_vout(**{k: v for k, v in base.items() if k != 'in_amount'})
    with pytest.raises(TypeError, match='fee not set'):
        make_vout(**{k: v for k, v in base.items() if k != 'fee'})


def test_str2bytes_encodes_as_latin1():
    """str2bytes -> bytes via latin-1 encoding (covers single-byte codepoints)."""
    from yubtc.crypto import str2bytes
    assert str2bytes('abc') == b'abc'
    assert str2bytes('') == b''


# ---------------------------------------------------------------------------
# *args guards: every multi-arg function rejects positional args after self.
# ---------------------------------------------------------------------------

def test_multi_arg_functions_reject_positional_args():
    """Functions taking >1 argument must be called kwargs-only."""
    from yubtc.crypto import (
        seed2bin, seed2privkey, privkey2privwif, sign_hash, sign_data,
        pubkey2addr, privkey2addr, make_vout,
    )
    from yubtc.crypto import seed2privkey as sk
    seed2privkey(seed='qwe', nonce=0, passphrase='')  # sanity: kwargs path still works
    # seed2bin
    with pytest.raises(TypeError, match='only kwargs allowed'):
        seed2bin('qwe', 0, passphrase='')
    # seed2privkey
    with pytest.raises(TypeError, match='only kwargs allowed'):
        sk('qwe', 0)
    # privkey2privwif
    with pytest.raises(TypeError, match='only kwargs allowed'):
        privkey2privwif(b'\x11' * 32, True)
    # sign_hash
    with pytest.raises(TypeError, match='only kwargs allowed'):
        sign_hash(b'\x11' * 32, b'\x00' * 32)
    # sign_data
    with pytest.raises(TypeError, match='only kwargs allowed'):
        sign_data(b'\x11' * 32, b'data')
    # pubkey2addr
    with pytest.raises(TypeError, match='only kwargs allowed'):
        pubkey2addr(b'\x00' * 64, True)
    # privkey2addr
    with pytest.raises(TypeError, match='only kwargs allowed'):
        privkey2addr(b'\x11' * 32, True)
    # make_vout
    with pytest.raises(TypeError, match='only kwargs allowed'):
        make_vout(b'\x00' * 20, b'\x00' * 20, 100_000, 50_000, 1_000)


def test_bytes2str_decodes_via_chr():
    """bytes2str -> str via chr() of each byte value."""
    from yubtc.crypto import bytes2str
    assert bytes2str(b'abc') == 'abc'
    assert bytes2str(bytes([65, 66, 67])) == 'ABC'


def test_str2list_splits_into_characters():
    """str2list -> list of single-char strings."""
    from yubtc.crypto import str2list
    assert str2list('abc') == ['a', 'b', 'c']
    assert str2list('') == []
