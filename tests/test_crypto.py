import pytest

@pytest.mark.parametrize(
        'compressed, seed, privhex, privwif, address',
        [
            (False, 'qwe', '1814825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0455', b'5Hztg9Lf6fPida3GtdxhzmC6gTh98oQ6dGPotiFWMBSanCVcqBb', b'16toxZ1pUrKbw7Ripem1X4aGxmY6b5qSCz'),
            (True, 'qwe', '1814825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0455', b'Kx2X5mom9zTGkQq38v8swx3z5ApAuRnwq4wfyF52Y55v6Ke5dRq5', b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'),
            (False, '12345', '28820488de48082a13c570e68e1295e0207c6ef826a685c220d10fd6d8b95d49', b'5J88JQkRPEffAwVL73kwtDzGFqtBFiCsFXajzb9ytmCZbs4VSUY', b'1MN1fFX2xmKS1qZXyhw5EUpS9Laa2HaeYX'),
            (True, '12345', '28820488de48082a13c570e68e1295e0207c6ef826a685c220d10fd6d8b95d49', b'KxaTDqped9KdUsW3KhAyF6KkLWktFvsNo7yvmBke7U62tWmMs8dk', b'1sW6JDNWppzUjQr8jjQ9KJmVx92ooKEd6'),
        ]
    )
def test(compressed, seed, privhex, privwif, address):
    from yubtc.crypto import seed2privkey, privkey2privwif, privkey2addr
    privkey = seed2privkey(seed)
    assert privkey.hex() == privhex
    assert privkey2privwif(privkey, compressed) == privwif
    assert privkey2addr(privkey, compressed) == address

"""
this test included in main test()
def test_bin2privkey():
    import axolotl_curve25519 as curve
    from yubtc.crypto import seed2privkey, seed2bin
    seed = 'my test seed'
    assert seed2privkey(seed) == curve.generatePrivateKey(seed2bin(seed))
"""


# ---------------------------------------------------------------------------
# seed2bin: the KDF. Output is 32 bytes; deterministic in seed and nonce.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('seed, nonce, expected', [
    ('qwe',  0, '1c14825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0455'),
    ('12345', 0, '2d820488de48082a13c570e68e1295e0207c6ef826a685c220d10fd6d8b95d89'),
    ('',     0, '07407db254d500c0b614d835abe6a525a80eada073a8f67e6350cd18678e8cf6'),
    ('qwe',  7, '1f2b3272b320b5be8dae398655d2e25924a9ba9676b78b9eb095691fcb2c8c23'),
])
def test_seed2bin_known_answers(seed, nonce, expected):
    from yubtc.crypto import seed2bin
    out = seed2bin(seed, nonce)
    assert len(out) == 32
    assert out.hex() == expected


def test_seed2bin_nonce_changes_output():
    """The nonce is meant to derive distinct addresses from one seed."""
    from yubtc.crypto import seed2bin
    assert seed2bin('qwe', 0) != seed2bin('qwe', 1)
    assert seed2bin('qwe', 0) != seed2bin('qwe', 7)


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
    from yubtc.crypto import seed2bin, bin2privkey, seed2privkey
    for seed in ('qwe', '12345', '', 'a much longer seed phrase here'):
        assert seed2privkey(seed) == bin2privkey(seed2bin(seed))


def test_seed2privkey_nonce_changes_privkey():
    from yubtc.crypto import seed2privkey
    assert seed2privkey('qwe', 0) != seed2privkey('qwe', 1)


# ---------------------------------------------------------------------------
# privkey2privwif / privwif2privkey: round-trip plus contract checks.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('privkey', [
    b'\x00' * 32,
    b'\xff' * 32,
    b'\xab' * 32,
    bytes.fromhex('1814825e69d2e72eabfbec9c0168f5689dcc26509aa2a8590d859a90402f0455'),
])
def test_privwif_roundtrip(privkey):
    from yubtc.crypto import privkey2privwif, privwif2privkey
    for compressed in (True, False):
        wif = privkey2privwif(privkey, compressed)
        decoded, c = privwif2privkey(wif)
        assert decoded == privkey
        assert c == compressed


def test_privwif_default_is_compressed():
    """Bitcoin convention: privkey2privwif() with no `compressed` kwarg returns a compressed WIF (starts with K/L)."""
    from yubtc.crypto import privkey2privwif
    privkey = b'\x11' * 32
    assert privkey2privwif(privkey)[:1] in (b'K', b'L')


def test_privwif2privkey_rejects_bad_prefix():
    from yubtc.crypto import privwif2privkey, PREFIX_P2PKH
    from yubtc.base58check import base58CheckEncode
    not_a_privkey = base58CheckEncode(bytes([PREFIX_P2PKH]) + b'\x00' * 20)
    with pytest.raises(Exception):
        privwif2privkey(not_a_privkey)


# ---------------------------------------------------------------------------
# privkey2pubkey / pubkey2pubwif: public-key derivation and serialisation.
# ---------------------------------------------------------------------------

def test_privkey2pubkey_length_and_determinism():
    """The pubkey is 64 bytes (uncompressed, no leading 0x04) and deterministic."""
    from yubtc.crypto import seed2privkey, privkey2pubkey
    privkey = seed2privkey('qwe')
    a = privkey2pubkey(privkey)
    b = privkey2pubkey(privkey)
    assert len(a) == 64
    assert a == b


def test_privkey2pubkey_known_answer():
    from yubtc.crypto import seed2privkey, privkey2pubkey
    expected = 'eff5d63eedb62d21b86780b468e5ca9c2f938be2f0b23c05cd76ae1508a178d0' \
               '24d7de8d887bee3288e5afb66ff648f05f47cd6e6d21978c805a5cfe0983f301'
    assert privkey2pubkey(seed2privkey('qwe')).hex() == expected


@pytest.mark.parametrize('compressed, expected', [
    (True,  '03eff5d63eedb62d21b86780b468e5ca9c2f938be2f0b23c05cd76ae1508a178d0'),
    (False, '04eff5d63eedb62d21b86780b468e5ca9c2f938be2f0b23c05cd76ae1508a178d0'
            '24d7de8d887bee3288e5afb66ff648f05f47cd6e6d21978c805a5cfe0983f301'),
])
def test_pubkey2pubwif_serialisation(compressed, expected):
    """Compressed: 33 bytes, prefix 0x02/0x03 by parity of y. Uncompressed: 65 bytes, prefix 0x04."""
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    pubkey = privkey2pubkey(seed2privkey('qwe'))
    out = pubkey2pubwif(pubkey, compressed)
    assert len(out) == (33 if compressed else 65)
    assert out.hex() == expected


def test_pubkey2pubwif_picks_even_prefix_for_even_y():
    """The last byte of y determines the prefix under compressed serialisation."""
    from yubtc.crypto import pubkey2pubwif, PREFIX_PUBKEY_EVEN, PREFIX_PUBKEY_ODD
    # 32 zero bytes -> last byte 0x00, even parity -> 0x02
    assert pubkey2pubwif(b'\x00' * 32 + b'\x00' * 32, True)[0] == PREFIX_PUBKEY_EVEN
    # 32 zero bytes + 0x01 -> odd parity -> 0x03
    assert pubkey2pubwif(b'\x00' * 32 + b'\x01' * 32, True)[0] == PREFIX_PUBKEY_ODD
    # 0xFF -> odd parity -> 0x03
    assert pubkey2pubwif(b'\x00' * 32 + b'\xff' * 32, True)[0] == PREFIX_PUBKEY_ODD


def test_pubkey2pubwif_uncompressed_uses_full_prefix():
    from yubtc.crypto import pubkey2pubwif, PREFIX_PUBKEY_FULL
    out = pubkey2pubwif(b'\x00' * 64, False)
    assert out[0] == PREFIX_PUBKEY_FULL


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
    import ecdsa
    privkey = seed2privkey('qwe')
    digest = b'\x42' * 32
    for _ in range(3):
        sig = sign_hash(privkey, digest)
        # DER structure: 0x30 [len] 0x02 [r-len] r 0x02 [s-len] s
        assert sig[0] == 0x30
        r_len = sig[3]
        assert sig[2] == 0x02
        assert sig[4 + r_len] == 0x02
        s_len = sig[5 + r_len]
        s = int.from_bytes(sig[6 + r_len:6 + r_len + s_len], 'big')
        # low-s: s must be <= n/2
        assert s <= ecdsa.SECP256k1.order // 2


def test_sign_hash_verifies():
    from yubtc.crypto import seed2privkey, sign_hash
    import ecdsa
    privkey = seed2privkey('qwe')
    digest = b'\x42' * 32
    sig = sign_hash(privkey, digest)
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    assert sk.verifying_key.verify_digest(sig, digest, sigdecode=ecdsa.util.sigdecode_der)


def test_sign_data_verifies():
    """sign_data(data) signs sha256(sha256(data)) and produces a valid DER signature."""
    from yubtc.crypto import seed2privkey, sign_data
    from yubtc.hash import sha256
    import ecdsa
    privkey = seed2privkey('qwe')
    sig = sign_data(privkey, b'abc')
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    assert sk.verifying_key.verify_digest(
        sig, sha256(sha256(b'abc')), sigdecode=ecdsa.util.sigdecode_der,
    )


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
    addr = privkey2addr(seed2privkey('qwe'), True)
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
    with pytest.raises(Exception):
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
    src = privkey2addr(seed2privkey('qwe'), True)
    dst = privkey2addr(seed2privkey('asdf'), True)
    vouts, cashback, amount = make_vout(src, dst, 100_000, None, 1_000)
    assert cashback == 0
    assert amount == 99_000
    assert len(vouts) == 1
    assert vouts[0].amount == 99_000
    # The single output locks the destination, not the source.
    assert vouts[0].script.hex() == '76a914d9d50a8ac051c555bf9a514aee0e4835efb3273888ac'


def test_make_vout_drains_when_amount_plus_fee_equals_input():
    """`amount + fee == in_amount` is the explicit form of "send everything"."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(seed2privkey('qwe'), True)
    dst = privkey2addr(seed2privkey('asdf'), True)
    vouts, cashback, amount = make_vout(src, dst, 100_000, 99_000, 1_000)
    assert cashback == 0
    assert amount == 99_000
    assert len(vouts) == 1 and vouts[0].amount == 99_000


def test_make_vout_sends_change_back_to_src():
    """Anything left over after amount+fee is routed back to the source address."""
    from yubtc.crypto import make_vout, seed2privkey, privkey2addr
    src = privkey2addr(seed2privkey('qwe'), True)
    dst = privkey2addr(seed2privkey('asdf'), True)
    vouts, cashback, amount = make_vout(src, dst, 100_000, 40_000, 1_000)
    assert cashback == 59_000
    assert amount == 40_000
    assert len(vouts) == 2
    # Output order: [change (back to src), payment (to dst)].
    assert vouts[0].amount == 59_000
    assert vouts[0].script.hex() == '76a914e96b5b4561e70170c16f51ca30a9429e3bede97788ac'
    assert vouts[1].amount == 40_000
    assert vouts[1].script.hex() == '76a914d9d50a8ac051c555bf9a514aee0e4835efb3273888ac'
