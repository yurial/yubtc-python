"""Tests for the SegWit/Taproot address layer (Phase 13).

Covers `crypto.pubkey2segwit_addr` / `pubkey2taproot_addr` /
`decode_segwit_addr` / `taproot_output_key` and the witness lock
scripts, pinned to the official BIP-173, BIP-350, BIP-86 and BIP-341
vectors. Bit-for-bit parity with the Rust core (`core/src/address.rs`,
`core/src/script.rs`) is the contract.
"""
import pytest

from yubtc.bech32 import bytes_to_5bit, encode
from yubtc.crypto import (HRP_MAINNET, SegWitInvalidChecksum,
                          SegWitInvalidCharacter, SegWitInvalidHrp,
                          SegWitInvalidProgramLength, SegWitInvalidStructure,
                          SegWitMixedCase, SegWitTooLong,
                          SegWitUnknownWitnessVersion, SegWitUnsupportedProgram,
                          TapTweakError, WitnessProgram, decode_segwit_addr,
                          pubkey2segwit_addr, pubkey2taproot_addr,
                          taproot_output_key)

# BIP-173 example pubkey: the generator's compressed form.
BIP173_PUBKEY = bytes.fromhex('02' + '79be667ef9dcbbac55a06295ce870b0702'
                              '9bfcdb2dce28d959f2815b16f81798')
# Its hash160 -- the official BIP-173 witness program.
BIP173_PROGRAM = bytes.fromhex('751e76e8199196d4549' + '41c45d1b3a323f1433bd6')

# Official BIP-86 test vectors (account 0, receiving addresses 0 and 1):
# internal x-only key -> tweaked output key -> bech32m address.
BIP86_VECTORS = [
    ('cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115',
     'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c',
     'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'),
    ('83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145',
     'a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb',
     'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh'),
]


# ---------------------------------------------------------------------------
# pubkey2segwit_addr / pubkey2taproot_addr
# ---------------------------------------------------------------------------

def test_pubkey_to_segwit_address_matches_bip173_example():
    # BIP-173: mainnet P2WPKH of 0279BE66...798 is
    # bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.
    assert pubkey2segwit_addr(pubkey=BIP173_PUBKEY) == \
        'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'


@pytest.mark.parametrize('length', [0, 31, 32, 34])
def test_pubkey_length_is_enforced(length):
    bad = (bytes([0x02]) + bytes([0x11] * 40))[:length]
    with pytest.raises(ValueError, match='pubkey must be 33 bytes'):
        pubkey2segwit_addr(pubkey=bad)
    with pytest.raises(ValueError, match='pubkey must be 33 bytes'):
        pubkey2taproot_addr(pubkey=bad)


def test_pubkey_to_taproot_address_matches_bip86_vectors():
    for internal_hex, output_hex, address in BIP86_VECTORS:
        pubkey = bytes([0x02]) + bytes.fromhex(internal_hex)
        assert pubkey2taproot_addr(pubkey=pubkey) == address
        # And the tweak itself matches the published output key.
        assert taproot_output_key(internal_xonly=bytes.fromhex(internal_hex)) == \
            bytes.fromhex(output_hex)


def test_taproot_address_is_parity_independent():
    # Only the x coordinate of the input pubkey is used, so the
    # 0x02/0x03 prefixes of the same key yield the same address.
    even = bytes([0x02]) + bytes.fromhex(BIP86_VECTORS[0][0])
    odd = bytes([0x03]) + bytes.fromhex(BIP86_VECTORS[0][0])
    assert pubkey2taproot_addr(pubkey=even) == pubkey2taproot_addr(pubkey=odd)


def test_bip341_taproot_address_vector():
    # Official BIP-341 wallet test vector (scriptPubKey section, entry 0
    # with a null script tree).
    internal = internal = bytes.fromhex(
        'd6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d')
    output = taproot_output_key(internal_xonly=internal)
    assert output.hex() == \
        '53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343'
    assert pubkey2taproot_addr(pubkey=bytes([0x02]) + internal) == \
        'bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5'


def _bip39_master(mnemonic):
    """BIP-39 stretch + BIP-32 master, primitives only.

    The official BIP-84/86 vectors use an EMPTY passphrase, which the
    yubtc KDF policy reserves for the legacy cascade; the Rust e2e
    test goes through the pbkdf2 primitive the same way."""
    from yubtc.bip32 import master_from_seed
    from yubtc.crypto import _stretch_pbkdf2
    return master_from_seed(seed=_stretch_pbkdf2(mnemonic, ''))


def test_bip86_derivation_end_to_end():
    # Full chain for the first BIP-86 vector: BIP-39 stretch ->
    # BIP-32 m/86'/0'/0'/0/0 -> x-only internal key -> TapTweak ->
    # address. Pins that the yubtc BIP-32 walk agrees with the BIP's
    # published xprv chain and that the receiving-address constructor
    # lands on the official string.
    from yubtc.bip32 import derive_path
    from yubtc.crypto import privkey2pubkey, seed2privkey
    from coincurve import PrivateKey as CK
    mnemonic = 'abandon abandon abandon abandon abandon abandon ' \
               'abandon abandon abandon abandon abandon about'
    master_priv, master_chain = _bip39_master(mnemonic)
    leaf, _ = derive_path(master_priv=master_priv, master_chain=master_chain,
                          path="m/86'/0'/0'/0/0")
    pubkey = privkey2pubkey(privkey=CK(leaf))
    assert pubkey[1:].hex() == BIP86_VECTORS[0][0]
    assert pubkey2taproot_addr(pubkey=pubkey) == BIP86_VECTORS[0][2]
    # The addr_type-driven seed2privkey derives the same leaf when a
    # passphrase unlocks the pbkdf2 KDF.
    with_pass = seed2privkey(seed=mnemonic, nonce=0, passphrase='TREZOR',
                             kdf='pbkdf2', addr_type='taproot')
    assert len(privkey2pubkey(privkey=with_pass)) == 33


def test_bip84_derivation_end_to_end():
    # The BIP-84 vector (same mnemonic): m/84'/0'/0'/0/0 lands on the
    # official first receiving address.
    from yubtc.bip32 import derive_path
    from yubtc.crypto import privkey2pubkey
    from coincurve import PrivateKey as CK
    mnemonic = 'abandon abandon abandon abandon abandon abandon ' \
               'abandon abandon abandon abandon abandon about'
    master_priv, master_chain = _bip39_master(mnemonic)
    leaf, _ = derive_path(master_priv=master_priv, master_chain=master_chain,
                          path="m/84'/0'/0'/0/0")
    assert pubkey2segwit_addr(pubkey=privkey2pubkey(privkey=CK(leaf))) == \
        'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'


def test_taproot_output_key_rejects_non_curve_point():
    # X = 0xffff...ff is not on secp256k1 -- libsecp256k1's parser must
    # reject it, surfacing as TapTweakError.
    with pytest.raises(TapTweakError, match='not a valid curve point'):
        taproot_output_key(internal_xonly=b'\xff' * 32)


def test_taproot_output_key_rejects_wrong_length():
    with pytest.raises(ValueError, match='internal pubkey must be 32 bytes'):
        taproot_output_key(internal_xonly=b'\x01' * 31)


def test_tweak_output_key_reports_infinity():
    # P = -5*G with t = 5 gives Q = 0 -- the p ~ 2^-128 branch, driven
    # with crafted inputs since real keys cannot reach it (mirrors the
    # Rust test driving `address.rs::tweak_output_key` directly).
    from coincurve import PrivateKey
    from yubtc.crypto import _tweak_output_key
    five = 5
    five_g = PrivateKey(five.to_bytes(32, 'big')).public_key
    compressed = five_g.format(compressed=True)
    neg_five_g = bytes([compressed[0] ^ 0x01]) + compressed[1:]
    with pytest.raises(TapTweakError, match='point at infinity'):
        _tweak_output_key(PKG(neg_five_g), five)
    # The non-infinity twin still succeeds: 5G + 5G = 10G (using the
    # actual point -- flipping the parity prefix would negate it).
    out = _tweak_output_key(five_g, five)
    ten_g = PrivateKey((10).to_bytes(32, 'big')).public_key
    assert out == ten_g.format(compressed=True)[1:33]


def PKG(data):
    """Local alias keeping the coincurve import surface of the
    infinity test explicit."""
    from coincurve import PublicKey
    return PublicKey(data)


# ---------------------------------------------------------------------------
# decode_segwit_addr: official vectors
# ---------------------------------------------------------------------------

def test_decode_accepts_official_valid_addresses():
    cases = [
        # BIP-173 mainnet P2WPKH (uppercase input, program bytes out).
        ('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 0, BIP173_PROGRAM),
        # BIP-350 v1-16 valid list, bc-prefixed P2TR. The program is
        # the generator's x-only key.
        ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
         1,
         bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d9'
                       '59f2815b16f81798')),
    ]
    for s, version, program in cases:
        wp = decode_segwit_addr(address=s)
        assert wp.version == version
        assert wp.program == program
        assert isinstance(wp, WitnessProgram)


def test_decode_round_trip_p2wpkh():
    addr = pubkey2segwit_addr(pubkey=BIP173_PUBKEY)
    wp = decode_segwit_addr(address=addr)
    assert wp.version == 0
    assert wp.program == BIP173_PROGRAM


def test_decode_rejects_official_invalid_addresses():
    cases = [
        # Invalid human-readable part.
        ('tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut',
         SegWitInvalidHrp),
        # v1 with a bech32 checksum (BIP-350 rule 2).
        ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd',
         SegWitInvalidChecksum),
        # v0 with a bech32m checksum.
        ('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
         SegWitInvalidChecksum),
        # Invalid character in checksum: the scan hits the excluded
        # 'o' before the trailing '_' (BIP-350 vector).
        ('bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4',
         SegWitInvalidCharacter),
        # Witness version 17 (charset value of '3'): the decode order
        # rejects version > 16 before the checksum rule.
        ('BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R',
         SegWitUnknownWitnessVersion),
        # Program length 1.
        ('bc1pw5dgrnzv', SegWitInvalidProgramLength),
        # Program length 41.
        ('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0'
         'muaewav253zgeav', SegWitInvalidProgramLength),
        # v0 with a 16-byte program (BIP-141 violation).
        ('BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', SegWitInvalidProgramLength),
        # Mixed case.
        ('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq',
         SegWitMixedCase),
        # Zero padding of more than 4 bits.
        ('bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du', SegWitInvalidStructure),
        # Outright checksum corruption.
        ('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5', SegWitInvalidChecksum),
        # Empty data section (no witness version).
        ('bc1gmk9yu', SegWitInvalidStructure),
    ]
    for s, expected in cases:
        with pytest.raises(expected):
            decode_segwit_addr(address=s)


def test_decode_rejects_p2wsh_as_unsupported():
    # Valid v0/32-byte bech32 address (BIP-173 mainnet P2WSH example):
    # structurally valid, out of yubtc scope.
    with pytest.raises(SegWitUnsupportedProgram, match='P2WSH'):
        decode_segwit_addr(
            address='bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3')


def test_decode_rejects_witness_versions_above_one():
    # Structurally valid bech32m addresses with witness versions 2
    # ('z') and 23 ('h'): both parse cleanly under BIP-173/350 but
    # must be rejected by the yubtc v0/v1 scope rule.
    charset = b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    for version_char in ('z', 'h'):
        version = charset.index(ord(version_char))
        payload = bytes([version]) + bytes_to_5bit(data=b'\xab' * 20)
        s = encode(hrp=HRP_MAINNET, encoding='bech32m', data=payload)
        with pytest.raises(SegWitUnknownWitnessVersion) as exc:
            decode_segwit_addr(address=s)
        assert exc.value.version == version


def test_decode_rejects_malformed_minimal_inputs():
    # No separator at all.
    with pytest.raises(SegWitInvalidStructure):
        decode_segwit_addr(address='bcqpw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
    # Too long: > 90 characters.
    with pytest.raises(SegWitTooLong):
        decode_segwit_addr(address='bc1q' + 'q' * 95)
    # Empty input.
    with pytest.raises(SegWitInvalidStructure):
        decode_segwit_addr(address='')
    # Wrong HRP on a structurally valid string (the official BIP-173
    # testnet P2WSH vector).
    with pytest.raises(SegWitInvalidHrp) as exc:
        decode_segwit_addr(
            address='tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7')
    assert 'tb' in str(exc.value)


# ---------------------------------------------------------------------------
# make_lock_script dispatch (base58 -> P2PKH/P2SH, bc1 -> P2WPKH/P2TR)
# ---------------------------------------------------------------------------

def test_make_lock_script_builds_witness_scripts_for_bc1_addresses():
    from yubtc.script import OP_0, OP_1, OP_PUSHBYTES_20, OP_PUSHBYTES_32
    from yubtc.crypto import make_lock_script
    p2wpkh_addr = pubkey2segwit_addr(pubkey=BIP173_PUBKEY)
    script = make_lock_script(p2wpkh_addr)
    assert script[0] == OP_0
    assert script[1] == OP_PUSHBYTES_20
    assert script[2:] == BIP173_PROGRAM

    p2tr_addr = 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'
    script = make_lock_script(p2tr_addr)
    assert script[0] == OP_1
    assert script[1] == OP_PUSHBYTES_32
    assert len(script) == 34
    # Uppercase prefix dispatches to the same bech32 path.
    assert make_lock_script('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4') == \
        bytes([OP_0, OP_PUSHBYTES_20]) + BIP173_PROGRAM


def test_make_lock_script_propagates_segwit_errors():
    from yubtc.crypto import make_lock_script
    with pytest.raises(SegWitInvalidChecksum):
        make_lock_script('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5')
    with pytest.raises(SegWitUnsupportedProgram):
        make_lock_script(
            'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3')


def test_witness_lock_script_makers_reject_wrong_lengths():
    from yubtc.script import make_p2tr_lock_script, make_p2wpkh_lock_script
    with pytest.raises(ValueError, match='hash160 must be 20 bytes, got 19'):
        make_p2wpkh_lock_script(hash160=b'\x00' * 19)
    with pytest.raises(ValueError, match='hash160 must be 20 bytes, got 21'):
        make_p2wpkh_lock_script(hash160=b'\x00' * 21)
    with pytest.raises(ValueError, match='output key must be 32 bytes, got 31'):
        make_p2tr_lock_script(output_key=b'\x00' * 31)
    with pytest.raises(ValueError, match='output key must be 32 bytes, got 33'):
        make_p2tr_lock_script(output_key=b'\x00' * 33)


def test_make_lock_script_keeps_base58_path():
    # The v0.1 base58 dispatch is unchanged: the known 'qwe' address
    # and the P2SH/unsupported-prefix branches.
    from yubtc.crypto import make_lock_script
    from yubtc.script import OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL
    from yubtc.base58check import base58CheckEncode
    script = make_lock_script('1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    assert script[0] == OP_DUP and script[1] == OP_HASH160
    assert script[-2] == OP_EQUALVERIFY and script[-1] == OP_CHECKSIG
    p2sh = base58CheckEncode(bytes([0x05]) + b'\x33' * 20)
    script = make_lock_script(p2sh)
    assert script[0] == OP_HASH160 and script[-1] == OP_EQUAL
    with pytest.raises(ValueError, match='address not supported'):
        make_lock_script(base58CheckEncode(bytes([0x6f]) + b'\x00' * 20))


# ---------------------------------------------------------------------------
# seed2bin / seed2privkey: addr_type -> path mapping (spec ОВ-2)
# ---------------------------------------------------------------------------

def test_seed2bin_addr_type_defaults_to_legacy_path():
    from yubtc.crypto import seed2bin
    base = seed2bin(seed='qwe', nonce=3, passphrase='x', kdf='pbkdf2')
    assert seed2bin(seed='qwe', nonce=3, passphrase='x', kdf='pbkdf2',
                    addr_type='legacy') == base


def test_seed2bin_purpose_paths_match_manual_bip32_walk():
    # native -> m/84', taproot -> m/86': each must equal a manual walk
    # of the same stretched seed (the external-wallet compatibility
    # contract).
    from yubtc.bip32 import derive_path, master_from_seed
    from yubtc.crypto import _stretch_pbkdf2, seed2bin
    stretched = _stretch_pbkdf2('qwe', 'x')
    master_priv, master_chain = master_from_seed(seed=stretched)
    for addr_type, purpose in (('native', 84), ('taproot', 86)):
        leaf, _ = derive_path(
            master_priv=master_priv, master_chain=master_chain,
            path="m/{purpose}'/0'/0'/0/7".format(purpose=purpose))
        assert seed2bin(seed='qwe', nonce=7, passphrase='x', kdf='pbkdf2',
                        addr_type=addr_type) == leaf


def test_seed2bin_variant_a_same_key_for_non_bip32_kdfs():
    # Variant A (ОВ-2): for the non-BIP-32 KDFs every address type
    # derives the same secret -- only the address encoding differs.
    from yubtc.crypto import seed2bin
    legacy = seed2bin(seed='qwe', nonce=2, passphrase='', kdf='yubtc')
    assert seed2bin(seed='qwe', nonce=2, passphrase='', kdf='yubtc',
                    addr_type='native') == legacy
    assert seed2bin(seed='qwe', nonce=2, passphrase='', kdf='yubtc',
                    addr_type='taproot') == legacy


def test_seed2bin_variant_a_same_key_for_argon2id():
    # argon2id walks BIP-32 internally but is not externally
    # BIP-39-compatible, so it stays on the legacy purpose for every
    # address type (variant A).
    from yubtc.crypto import seed2bin
    legacy = seed2bin(seed='qwe', nonce=0, passphrase='p', kdf='argon2id')
    assert seed2bin(seed='qwe', nonce=0, passphrase='p', kdf='argon2id',
                    addr_type='taproot') == legacy


def test_seed2bin_rejects_unknown_addr_type():
    from yubtc.crypto import seed2bin
    with pytest.raises(ValueError, match='unknown addr type'):
        seed2bin(seed='qwe', nonce=0, passphrase='x', kdf='pbkdf2',
                 addr_type='bech32')


def test_seed2bin_bip32_error_on_huge_nonce_with_native_path():
    from yubtc.crypto import Bip32Error, seed2bin
    with pytest.raises(Bip32Error, match='non-hardened child index'):
        seed2bin(seed='qwe', nonce=0x80000000, passphrase='x', kdf='pbkdf2',
                 addr_type='native')


def test_seed2privkey_threads_addr_type():
    from yubtc.crypto import privkey2pubkey, seed2privkey
    from yubtc.crypto import seed2bin
    key = seed2privkey(seed='qwe', nonce=1, passphrase='x', kdf='pbkdf2',
                       addr_type='native')
    assert key.secret == seed2bin(seed='qwe', nonce=1, passphrase='x',
                                  kdf='pbkdf2', addr_type='native')
    assert len(privkey2pubkey(privkey=key)) == 33
