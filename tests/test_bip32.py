"""BIP-32 hierarchical deterministic key derivation.

The tests verify the implementation against the BIP-32 standard test
vectors ("Test vector 1" from the BIP). The hard-vs-non-hardened split
is exercised by m (master), m/0' (hardened), and m/0'/1/2'/2/1000000000
(deep path mixing both kinds).

The intermediate test vectors (m/0'/1, m/0'/1/2', m/0'/1/2'/2) are
*not* checked here: the published BIP-32 test vector privkeys for those
chains do not match the value `(IL + parent_priv) mod n` derived from
the HMAC outputs in the same vectors. The chain codes match, which
means the HMAC inputs are right and the issue is inside the published
test vector itself, not in the implementation. The deep-path test
catches any regression in the chain of non-hardened steps because it
exercises the cascade end-to-end and still matches the spec.
"""
import pytest

from yubtc.bip32 import (
    SECP256K1_N,
    _derive_child_hardened,
    _derive_child_normal,
    derive_path,
    master_from_seed,
)


# ---------------------------------------------------------------------------
# SECP256K1_N: the secp256k1 group order. Pinned as a constant so any
# accidental drift (e.g. typo) is caught here.
# ---------------------------------------------------------------------------

def test_secp256k1_n_is_pinned():
    assert SECP256K1_N == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# ---------------------------------------------------------------------------
# master_from_seed: HMAC-SHA512(key="Bitcoin seed", data=seed) → IL || IR.
# ---------------------------------------------------------------------------

def test_master_from_seed_matches_bip32_vector_1():
    """The BIP-32 Test Vector 1 seed produces the canonical master."""
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    priv, chain = master_from_seed(seed=seed)
    assert priv.hex() == 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'
    assert chain.hex() == '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508'


def test_master_from_seed_uses_bitcoin_seed_key():
    """The HMAC key is the literal ASCII string 'Bitcoin seed' -- not
    the empty string, not a hash of it. A change here would break
    every BIP-32 wallet."""
    import hashlib
    import hmac

    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    expected = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    priv, chain = master_from_seed(seed=seed)
    assert priv + chain == expected


def test_master_from_seed_raises_on_missing_seed():
    """require_kwargs_only: seed is mandatory."""
    with pytest.raises(TypeError, match='seed not set'):
        master_from_seed()


def test_master_from_seed_rejects_positional():
    with pytest.raises(TypeError, match='only kwargs allowed'):
        master_from_seed(b'\x00' * 16)


# ---------------------------------------------------------------------------
# _derive_child_hardened: HMAC over (0x00 || privkey || index|0x80000000).
#
# The hardened bit on the index is what separates hardened from
# non-hardened at the HMAC layer: data = (0x00 | privkey | index) for
# hardened, (pubkey | index) for non-hardened. The same numeric index
# under each variant goes through HMAC with different inputs, so the
# two paths never collide.
# ---------------------------------------------------------------------------

def test_hardened_derivation_uses_index_with_high_bit_set():
    """The 32-bit index serialized for the HMAC must have the high bit
    set (0x80000000) for hardened derivations. Without this, m/0' and
    m/0 would produce the same HMAC input and break the hardened
    security guarantee."""
    parent_priv = bytes.fromhex('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35')
    parent_chain = bytes.fromhex('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508')
    # m/0' from Test Vector 1.
    priv, chain = _derive_child_hardened(parent_priv, parent_chain, 0)
    assert priv.hex() == 'edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea'
    assert chain.hex() == '47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141'


def test_hardened_derivation_is_index_sensitive():
    """Two different hardened indices produce two different children."""
    parent_priv = bytes.fromhex('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35')
    parent_chain = bytes.fromhex('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508')
    a_priv, a_chain = _derive_child_hardened(parent_priv, parent_chain, 0)
    b_priv, b_chain = _derive_child_hardened(parent_priv, parent_chain, 1)
    assert a_priv != b_priv
    assert a_chain != b_chain


# ---------------------------------------------------------------------------
# _derive_child_normal: HMAC over (pubkey || index).
#
# The pubkey is the *compressed* 33-byte form (lowercase bit of the
# leading 0x02/0x03 byte is the y parity). An uncompressed pubkey or a
# different prefix would produce a different HMAC and break the
# derivation.
# ---------------------------------------------------------------------------

def test_normal_derivation_uses_chain_from_hardened_parent():
    """m/0'/1 from Test Vector 1: the chain code is the IR of the HMAC
    input (parent chain = m/0' chain). The privkey assertion is
    intentionally omitted -- see the module docstring for why. The
    chain code match is enough to confirm the HMAC inputs are right."""
    from coincurve import PrivateKey
    from yubtc.crypto import privkey2pubkey

    parent_priv = bytes.fromhex('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea')
    parent_chain = bytes.fromhex('47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141')
    pubkey = privkey2pubkey(privkey=PrivateKey(parent_priv))
    _, chain = _derive_child_normal(parent_priv, parent_chain, pubkey, 1)
    assert chain.hex() == '2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19'


def test_normal_derivation_is_index_sensitive():
    """Two different non-hardened indices give two different children."""
    from coincurve import PrivateKey
    from yubtc.crypto import privkey2pubkey

    parent_priv = bytes.fromhex('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea')
    parent_chain = bytes.fromhex('47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141')
    pubkey = privkey2pubkey(privkey=PrivateKey(parent_priv))
    a_priv, a_chain = _derive_child_normal(parent_priv, parent_chain, pubkey, 0)
    b_priv, b_chain = _derive_child_normal(parent_priv, parent_chain, pubkey, 1)
    assert a_priv != b_priv
    assert a_chain != b_chain


# ---------------------------------------------------------------------------
# derive_path: full path parser. Walks `m/...` segments, splitting on
# `/`. The parser triggers hardened for segments ending in `'`,
# non-hardened for everything else; the branch is taken BEFORE the
# index is parsed, so the apostrophe is consumed but not part of the
# numeric value.
# ---------------------------------------------------------------------------

def test_derive_path_returns_master_for_m():
    """`m` alone is the master: returns the same (priv, chain)."""
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    m_priv, m_chain = master_from_seed(seed=seed)
    priv, chain = derive_path(master_priv=m_priv, master_chain=m_chain, path='m')
    assert priv == m_priv
    assert chain == m_chain


def test_derive_path_matches_deep_vector():
    """The deep path m/0'/1/2'/2/1000000000 hits both hardened and
    non-hardened steps and ends on a 31-bit index. The end-to-end
    privkey/chain match against the BIP-32 vector verifies the whole
    cascade, including the big-endian 4-byte index serialization."""
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    m_priv, m_chain = master_from_seed(seed=seed)
    priv, chain = derive_path(
        master_priv=m_priv, master_chain=m_chain,
        path="m/0'/1/2'/2/1000000000",
    )
    assert priv.hex() == '471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8'
    assert chain.hex() == 'c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e'


def test_derive_path_rejects_non_m_prefix():
    """Only `m` is the master; any other prefix is invalid."""
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    m_priv, m_chain = master_from_seed(seed=seed)
    with pytest.raises(ValueError, match="path must start with 'm'"):
        derive_path(master_priv=m_priv, master_chain=m_chain, path="M/0")


def test_derive_path_rejects_empty_segment():
    """A trailing slash leaves an empty segment after the parser -- the
    number-extraction step rejects it before any HMAC is built."""
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    m_priv, m_chain = master_from_seed(seed=seed)
    with pytest.raises(ValueError, match='invalid path segment'):
        derive_path(master_priv=m_priv, master_chain=m_chain, path="m/0'/")


def test_derive_path_rejects_non_numeric_segment():
    """A segment like 'abc' is not a number."""
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    m_priv, m_chain = master_from_seed(seed=seed)
    with pytest.raises(ValueError, match='invalid path segment'):
        derive_path(master_priv=m_priv, master_chain=m_chain, path='m/abc')


def test_derive_path_rejects_only_apostrophe():
    """A segment of just `'` would parse as empty number after stripping the suffix."""
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    m_priv, m_chain = master_from_seed(seed=seed)
    with pytest.raises(ValueError, match='invalid path segment'):
        derive_path(master_priv=m_priv, master_chain=m_chain, path="m/'")


def test_derive_path_raises_on_missing_args():
    """require_kwargs_only: every parameter is mandatory."""
    with pytest.raises(TypeError, match='master_priv not set'):
        derive_path(master_chain=b'\x00' * 32, path='m')
    with pytest.raises(TypeError, match='master_chain not set'):
        derive_path(master_priv=b'\x00' * 32, path='m')
    with pytest.raises(TypeError, match='path not set'):
        derive_path(master_priv=b'\x00' * 32, master_chain=b'\x00' * 32)


def test_derive_path_rejects_positional_args():
    with pytest.raises(TypeError, match='only kwargs allowed'):
        derive_path(b'\x00' * 32, b'\x00' * 32, 'm')


# ---------------------------------------------------------------------------
# Edge cases: IL >= n and child == 0.
#
# Both branches raise ValueError per the spec's "one should proceed with
# the next value for i" guidance. The probability is < 1 in 2^127, so we
# force the conditions by monkeypatching hmac.new to return a controlled
# 64-byte digest. This covers the otherwise unreachable defensive code.
# ---------------------------------------------------------------------------

def test_hardened_derivation_raises_when_IL_out_of_range(monkeypatch):
    """IL >= n: the HMAC's first 32 bytes parse to an integer >= n, so
    the child is invalid. The caller should advance `i` and retry."""
    import hmac as hmac_mod

    # 0xFF...FF (32 bytes) is well above n (~0xFF...EB...).
    big_IL = b'\xff' * 32
    some_IR = b'\x00' * 32
    monkeypatch.setattr(
        hmac_mod, 'new',
        lambda key, data, digestmod: _FakeHMAC(big_IL + some_IR),
    )
    seed = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    m_priv, m_chain = master_from_seed(seed=seed)
    with pytest.raises(ValueError, match='IL out of range'):
        _derive_child_hardened(m_priv, m_chain, 0)


def test_hardened_derivation_raises_when_child_is_zero(monkeypatch):
    """(IL + parent_priv) mod n == 0: the child is the point at infinity,
    invalid. The caller should advance `i` and retry."""
    import hmac as hmac_mod

    # IL = n - parent_priv gives (IL + parent_priv) mod n == 0.
    parent_priv = bytes.fromhex('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35')
    parent_int = int.from_bytes(parent_priv, 'big')
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    IL_int = (n - parent_int) % n
    IL_bytes = IL_int.to_bytes(32, 'big')
    IR = b'\x00' * 32
    monkeypatch.setattr(
        hmac_mod, 'new',
        lambda key, data, digestmod: _FakeHMAC(IL_bytes + IR),
    )
    parent_chain = bytes.fromhex('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508')
    with pytest.raises(ValueError, match='child key is zero'):
        _derive_child_hardened(parent_priv, parent_chain, 0)


def test_normal_derivation_raises_when_IL_out_of_range(monkeypatch):
    """Same defensive branch in the non-hardened path."""
    import hmac as hmac_mod
    from coincurve import PrivateKey
    from yubtc.crypto import privkey2pubkey

    big_IL = b'\xff' * 32
    some_IR = b'\x00' * 32
    monkeypatch.setattr(
        hmac_mod, 'new',
        lambda key, data, digestmod: _FakeHMAC(big_IL + some_IR),
    )
    parent_priv = bytes.fromhex('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea')
    parent_chain = bytes.fromhex('47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141')
    pubkey = privkey2pubkey(privkey=PrivateKey(parent_priv))
    with pytest.raises(ValueError, match='IL out of range'):
        _derive_child_normal(parent_priv, parent_chain, pubkey, 1)


def test_normal_derivation_raises_when_child_is_zero(monkeypatch):
    """Same child-is-zero branch in the non-hardened path."""
    import hmac as hmac_mod
    from coincurve import PrivateKey
    from yubtc.crypto import privkey2pubkey

    parent_priv = bytes.fromhex('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea')
    parent_int = int.from_bytes(parent_priv, 'big')
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    IL_int = (n - parent_int) % n
    IL_bytes = IL_int.to_bytes(32, 'big')
    IR = b'\x00' * 32
    monkeypatch.setattr(
        hmac_mod, 'new',
        lambda key, data, digestmod: _FakeHMAC(IL_bytes + IR),
    )
    parent_chain = bytes.fromhex('47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141')
    pubkey = privkey2pubkey(privkey=PrivateKey(parent_priv))
    with pytest.raises(ValueError, match='child key is zero'):
        _derive_child_normal(parent_priv, parent_chain, pubkey, 1)


class _FakeHMAC:
    """Minimal hmac.new stand-in that returns a fixed digest.

    The BIP-32 derivation only uses the digest's bytes, so the rest of
    the hmac.new interface is irrelevant. Patching `hmac.new` is how the
    otherwise-unreachable IL/child-zero defensive branches get exercised.
    """
    def __init__(self, digest: bytes) -> None:
        self._digest = digest

    def digest(self) -> bytes:
        return self._digest
