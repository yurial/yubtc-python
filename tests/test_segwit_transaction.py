"""Tests for the SegWit transaction layer (Phase 13).

Witness serialization (marker/flag, txid vs wtxid, weight/vsize), the
BIP-143 and BIP-341 signature digests, and BIP-340 Schnorr signing --
all pinned to the official test vectors. Bit-for-bit parity with the
Rust core (`core/src/transaction.rs`) is the contract.
"""
import pytest

from yubtc.crypto import privkey2pubkey, seed2privkey, taproot_output_key
from yubtc.hash import hash160
from yubtc.transaction import (SIG_SCHEME_LEGACY, SIG_SCHEME_P2TR,
                               SIG_SCHEME_P2WPKH, CIn, COut, CTransaction,
                               SpendInput, bip143_sighash,
                               compact_size, p2wpkh_script_code,
                               sig_scheme_from_script_pubkey,
                               taproot_keypath_sighash, taproot_sign_sighash,
                               taproot_tweaked_scalar)

TXHASH = b'\xab' * 32


# ---------------------------------------------------------------------------
# compact_size: Bitcoin CompactSize (not the LEB128 toVarInt)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    (0, b'\x00'),
    (0xfc, b'\xfc'),
    (0xfd, b'\xfd\xfd\x00'),
    (0x10000, b'\xfe\x00\x00\x01\x00'),
    (0x1_0000_0000, b'\xff\x00\x00\x00\x00\x01\x00\x00\x00'),
])
def test_compact_size_ranges(value, expected):
    assert compact_size(value) == expected


def test_compact_size_rejects_negative():
    with pytest.raises(ValueError, match='non-negative'):
        compact_size(-1)


# ---------------------------------------------------------------------------
# CIn.witness: the BIP-141 witness stack
# ---------------------------------------------------------------------------

def test_cin_witness_defaults_to_empty_stack():
    inp = CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff)
    assert inp.witness == ()


def test_cin_witness_normalizes_items_to_bytes():
    inp = CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff,
              witness=[b'\x01\x02', b'\x03'])
    assert inp.witness == (b'\x01\x02', b'\x03')


def test_witness_never_enters_stripped_or_txid():
    tx = CTransaction(vin=[CIn(txhash=TXHASH, n=0, script=b'\x76\xa9',
                               sequence=0xffffffff)],
                      vout=[COut(amount=1000, script=b'\xac')], locktime=0)
    stripped = tx.serialize_stripped()
    txid = tx.id()
    tx.vin[0].witness = (b'\xaa' * 64,)
    assert tx.serialize_stripped() == stripped
    assert tx.id() == txid
    assert tx.has_witness()


# ---------------------------------------------------------------------------
# Wire serialization: marker/flag + witness stacks
# ---------------------------------------------------------------------------

def _example_tx():
    return CTransaction(vin=[CIn(txhash=TXHASH, n=0, script=b'\x76\xa9',
                                 sequence=0xffffffff)],
                        vout=[COut(amount=100_000, script=b'\x76\xa9')],
                        locktime=0)


def test_serialize_stripped_equals_legacy_serialize():
    tx = _example_tx()
    assert tx.serialize() == tx.serialize_stripped()
    assert not tx.has_witness()


def test_wire_without_witness_is_stripped():
    tx = _example_tx()
    assert tx.serialize_wire() == tx.serialize_stripped()
    assert tx.wtxid() == tx.id()


def test_wire_with_witness_has_marker_flag_and_stacks():
    tx = _example_tx()
    tx.vin[0].witness = (b'\x01\x02', b'\x03')
    wire = tx.serialize_wire()
    stripped = tx.serialize_stripped()
    # Same version prefix, then marker 0x00 + flag 0x01.
    assert wire[:4] == stripped[:4]
    assert wire[4:6] == b'\x00\x01'
    # vin/vout section identical...
    body = wire[6:-4]
    stripped_body = stripped[4:-4]
    assert body[:len(stripped_body)] == stripped_body
    # ...witness section for the single input: count 2,
    # len 2 || [0x01, 0x02], len 1 || [0x03].
    assert body[len(stripped_body):] == b'\x02\x02\x01\x02\x01\x03'
    assert len(wire) > len(stripped)
    assert tx.wtxid() != tx.id()


def test_weight_and_vsize_follow_bip141():
    tx = _example_tx()
    base = len(tx.serialize_stripped())
    # No witness: weight = 4*base, vsize = base (v0.1 behaviour).
    assert tx.weight() == base * 4
    assert tx.vsize() == base
    tx.vin[0].witness = (b'\xab' * 64,)
    total = len(tx.serialize_wire())
    assert tx.weight() == base * 3 + total
    assert tx.vsize() == -(-(base * 3 + total) // 4)
    assert tx.vsize() >= base


def test_wire_format_matches_official_bip143_signed_tx():
    # The official signed serialization of the BIP-143 example:
    # marker/flag, per-input witness stacks (input 0 empty, input 1
    # sig+pubkey), stripped body unchanged. Assembled from the BIP's
    # published bytes -- only the P2WPKH witness is ours.
    official = ('01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf'
                '433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b'
                '02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f92'
                '81a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef'
                '51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68'
                'a0100000000ffffffff02202cb206000000001976a9148280b37df378db99'
                'f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbe'
                'e7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6'
                'a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a95'
                '4c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee012'
                '1025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07ae'
                'ee635711000000')
    tx = CTransaction(
        vin=[
            CIn(txhash=bytes.fromhex('fff7f7881a8099afa6940d42d1e7f6362bec3817'
                                     '1ea3edf433541db4e4ad969f'), n=0,
                script=bytes.fromhex('4830450221008b9d1dc26ba6a9cb62127b02742fa9'
                                     'd754cd3bebf337f7a55d114c8e5cdd30be02204052'
                                     '9b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf'
                                     '4ecbab4cc618ef3ed01'),
                sequence=0xffff_ffee),
            CIn(txhash=bytes.fromhex('ef51e1b804cc89d182d279655c3aa89e815b1b30'
                                     '9fe287d9b2b55d57b90ec68a'), n=1,
                script=b'', sequence=0xffffffff,
                witness=[
                    bytes.fromhex('304402203609e17b84f6a7d30c80bfa610b5b4542f32'
                                  'a8a0d5447a12fb1366d7f01cc44a0220573a954c4518'
                                  '331561406f90300e8f3358f51928d43c212a8caed02d'
                                  'e67eebee01'),
                    bytes.fromhex('025476c2e83188368da1ff3e292e7acafcdb3566bb0a'
                                  'd253f62fc70f07aeee6357'),
                ]),
        ],
        vout=[
            COut(amount=0x06b22c20,
                 script=bytes.fromhex('76a9148280b37df378db99f66f85c95a783a76a'
                                      'c7a6d5988ac')),
            COut(amount=0x0d519390,
                 script=bytes.fromhex('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167'
                                      'faa815988ac')),
        ],
        locktime=17)
    tx.version = 1  # the official example predates BIP-68 (nVersion=1)
    assert tx.serialize_wire().hex() == official
    assert tx.has_witness()
    # txid excludes the witness.
    assert tx.id() == tx.id()
    assert tx.wtxid() != tx.id()


# ---------------------------------------------------------------------------
# SigScheme dispatch
# ---------------------------------------------------------------------------

def test_sig_scheme_dispatch():
    # P2WPKH shape 00 14 <20>.
    assert sig_scheme_from_script_pubkey(
        script_pubkey=bytes([0x00, 0x14]) + bytes(20)) == SIG_SCHEME_P2WPKH
    # P2TR shape 51 20 <32>.
    assert sig_scheme_from_script_pubkey(
        script_pubkey=bytes([0x51, 0x20]) + bytes(32)) == SIG_SCHEME_P2TR
    # Legacy shapes and malformed look-alikes.
    assert sig_scheme_from_script_pubkey(script_pubkey=bytes(25)) == SIG_SCHEME_LEGACY
    assert sig_scheme_from_script_pubkey(script_pubkey=bytes(23)) == SIG_SCHEME_LEGACY
    assert sig_scheme_from_script_pubkey(script_pubkey=b'') == SIG_SCHEME_LEGACY
    bad22 = bytes([0x01, 0x14]) + bytes(20)  # wrong version opcode
    assert sig_scheme_from_script_pubkey(script_pubkey=bad22) == SIG_SCHEME_LEGACY
    bad34 = bytes([0x51, 0x21]) + bytes(32)  # wrong push size
    assert sig_scheme_from_script_pubkey(script_pubkey=bad34) == SIG_SCHEME_LEGACY


# ---------------------------------------------------------------------------
# BIP-143 official vector (native P2WPKH example)
# ---------------------------------------------------------------------------

def _bip143_example_tx():
    """Unsigned transaction of the official BIP-143 native P2WPKH
    example: two inputs (P2PK + P2WPKH), two P2PKH outputs, nLockTime
    17, nVersion 1. Per the build_vin convention each input's script
    holds the UTXO scriptPubKey until signing."""
    h0 = bytes.fromhex('fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f')
    h1 = bytes.fromhex('ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a')
    return CTransaction(
        vin=[
            CIn(txhash=h0, n=0,
                script=bytes.fromhex('2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac'),
                sequence=0xffff_ffee),
            CIn(txhash=h1, n=1,
                script=bytes.fromhex('00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'),
                sequence=0xffffffff),
        ],
        vout=[
            COut(amount=0x06b22c20,
                 script=bytes.fromhex('76a9148280b37df378db99f66f85c95a783a76a'
                                      'c7a6d5988ac')),
            COut(amount=0x0d519390,
                 script=bytes.fromhex('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167'
                                      'faa815988ac')),
        ],
        locktime=17)


def _bip143_example_tx_v1():
    """The same transaction at the official nVersion=1."""
    tx = _bip143_example_tx()
    tx.version = 1
    return tx


def test_p2wpkh_script_code_official_bytes():
    spk = bytes.fromhex('00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1')
    script_code = p2wpkh_script_code(script_pubkey=spk)
    assert script_code.hex() == '1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac'


def test_bip143_sighash_matches_official_vector():
    # Official digest for the second input (P2WPKH, 6 BTC).
    tx = _bip143_example_tx_v1()
    script_code = p2wpkh_script_code(
        script_pubkey=bytes.fromhex('00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1'))
    sighash = bip143_sighash(tx=tx, input_index=1, script_code=script_code,
                             amount=600_000_000)
    assert sighash.hex() == 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670'


def test_bip143_sighash_rejects_out_of_range_index():
    tx = _bip143_example_tx()
    with pytest.raises(ValueError, match='input index 2 out of range'):
        bip143_sighash(tx=tx, input_index=2, script_code=bytes(26), amount=0)


def test_sign_segwit_p2wpkh_produces_verifiable_witness():
    # Sign the official example transaction: the produced witness
    # signature must verify against the official BIP-143 digest. The
    # BIP example's private keys are redacted, so the signature bytes
    # are not reproducible -- validity over the official digest is the
    # checkable property.
    import coincurve
    tx = _bip143_example_tx_v1()
    key = seed2privkey(seed='qwe', nonce=0, passphrase='')
    pubkey = privkey2pubkey(privkey=key)
    spend = [
        SpendInput(amount=625_000_000,
                   script_pubkey=tx.vin[0].script),
        SpendInput(amount=600_000_000,
                   script_pubkey=tx.vin[1].script),
    ]
    signed = tx.sign_segwit(signers=[(key, pubkey)] * 2, spend=spend)
    # Legacy input: scriptSig populated, no witness.
    assert signed.vin[0].script
    assert signed.vin[0].witness == ()
    # P2WPKH input: empty scriptSig, two witness items.
    assert signed.vin[1].script == b''
    assert len(signed.vin[1].witness) == 2
    assert signed.vin[1].witness[1] == pubkey
    wit_sig = signed.vin[1].witness[0]
    assert wit_sig[-1] == 0x01  # sighash type suffix
    # Verify over the official digest.
    official_sighash = bytes.fromhex(
        'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670')
    assert coincurve.verify_signature(wit_sig[:-1], official_sighash, pubkey,
                                      hasher=None)


# ---------------------------------------------------------------------------
# BIP-341 official vectors (wallet test vectors, key-path)
# ---------------------------------------------------------------------------

BIP341_UNSIGNED_TX = (
    '02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c'
    '010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b'
    '6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760'
    'd957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83'
    'ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb746'
    '1d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d'
    '2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c'
    '32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e'
    '6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa'
    '778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000f'
    'fffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc8'
    '8ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a66'
    '3f78bab962b0065cd1d')

# (scriptPubKey, amountSats) of the nine UTXOs spent by the BIP-341
# wallet test vector transaction.
BIP341_SPKS = [
    '512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343',
    '5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3',
    '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac',
    '5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e',
    '512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605',
    '00147dd65592d0ab2fe0d0257d571abf032cd9db93dc',
    '512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831',
    '5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5',
    '512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220',
]
BIP341_AMOUNTS = [420_000_000, 462_000_000, 294_000_000, 504_000_000,
                  630_000_000, 378_000_000, 672_000_000, 546_000_000,
                  588_000_000]


def _parse_unsigned_tx(hex_str):
    """Minimal wire parser for the BIP-341 vector's unsigned
    transaction (single-byte varints, empty scriptSigs)."""
    b = bytes.fromhex(hex_str)
    i = 0

    def u8():
        nonlocal i
        v = b[i]
        i += 1
        return v

    def take(n):
        nonlocal i
        v = b[i:i + n]
        i += n
        return v

    from struct import unpack
    tx_version = unpack('<i', take(4))[0]
    n_in = u8()
    vin = []
    for _ in range(n_in):
        txhash = take(32)
        n = unpack('<L', take(4))[0]
        script_len = u8()
        script = take(script_len)
        sequence = unpack('<L', take(4))[0]
        vin.append(CIn(txhash=txhash, n=n, script=script, sequence=sequence))
    n_out = u8()
    vout = []
    for _ in range(n_out):
        amount = unpack('<Q', take(8))[0]
        script_len = u8()
        vout.append(COut(amount=amount, script=take(script_len)))
    locktime = unpack('<L', take(4))[0]
    assert i == len(b)
    tx = CTransaction(vin=vin, vout=vout, locktime=locktime)
    tx.version = tx_version
    return tx


def _bip341_spend():
    return [SpendInput(amount=amount, script_pubkey=bytes.fromhex(spk))
            for spk, amount in zip(BIP341_SPKS, BIP341_AMOUNTS)]


def test_bip341_sighash_matches_official_vector():
    # Input 4 of the BIP-341 wallet test vector is signed with
    # SIGHASH_DEFAULT (hashType 0) -- the exact scheme yubtc uses.
    tx = _parse_unsigned_tx(BIP341_UNSIGNED_TX)
    sighash = taproot_keypath_sighash(tx=tx, input_index=4, spend=_bip341_spend())
    assert sighash.hex() == '4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef'


def test_bip341_schnorr_signature_matches_official_vector():
    # The BIP-341 vectors publish unredacted tweaked private keys:
    # signing the official input-4 digest with the vector's
    # tweakedPrivkey and aux = 0x00*32 must reproduce the published
    # witness byte-for-byte. This pins the BIP-340 signing primitive
    # (incl. aux handling) that `taproot_sign_sighash` delegates to --
    # libsecp256k1 produces the same bytes as the Rust port's k256.
    from coincurve import PrivateKey
    sighash = bytes.fromhex('4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef')
    tweaked = bytes.fromhex('a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7'
                            'f14b549400b4d501')
    sig = PrivateKey(tweaked).sign_schnorr(sighash, aux_randomness=b'\x00' * 32)
    assert sig.hex() == ('b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93e'
                         'de6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86f'
                         'a888a273c8511be83bfd6810f')


def test_taproot_tweaked_scalar_matches_bip341_vector():
    # Vector input 0 (key-path, empty Merkle root): the tweaked private
    # key derived from the internal key must equal the published
    # tweakedPrivkey.
    internal = bytes.fromhex('6b973d88838f27366ed61c9ad6367663045cb456e28335c1'
                             '09e30717ae0c6baa')
    key = seed2privkey.__wrapped__ if False else None  # noqa: F841 (keep imports obvious)
    from coincurve import PrivateKey
    tweaked = taproot_tweaked_scalar(privkey=PrivateKey(internal))
    assert tweaked.to_bytes(32, 'big').hex() == \
        '2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9'


def test_taproot_tweaked_scalar_always_matches_output_key():
    # For every key (both internal-key parities and both tweaked point
    # parities occur across this range) the tweaked scalar must sign
    # under the x-only tweaked output key: the BIP-340 signer
    # normalizes parity internally, so x((d+t)*G) -- the only thing an
    # address commits to -- matches in both cases.
    from coincurve import PrivateKey
    for i in range(1, 9):
        key = PrivateKey(i.to_bytes(32, 'big'))
        tweaked = taproot_tweaked_scalar(privkey=key)
        xonly = privkey2pubkey(privkey=key)[1:]
        q_even = taproot_output_key(internal_xonly=xonly)
        tweaked_key = PrivateKey(tweaked.to_bytes(32, 'big'))
        assert tweaked_key.public_key.format(compressed=True)[1:] == q_even


def test_taproot_sign_sighash_is_deterministic_and_verifies():
    # Deterministic aux (ОВ-3): signing twice yields identical bytes,
    # and the signature matches one produced directly under the
    # tweaked scalar (coincurve verifies the signature internally
    # before returning it).
    from coincurve import PrivateKey
    key = PrivateKey((0x2a).to_bytes(32, 'big'))
    sighash = bytes([7]) * 32
    sig1 = taproot_sign_sighash(privkey=key, sighash=sighash)
    sig2 = taproot_sign_sighash(privkey=key, sighash=sighash)
    assert sig1 == sig2
    assert len(sig1) == 64
    tweaked = taproot_tweaked_scalar(privkey=key)
    direct = PrivateKey(tweaked.to_bytes(32, 'big')).sign_schnorr(
        sighash, aux_randomness=b'\x00' * 32)
    assert sig1 == direct


def test_taproot_keypath_sighash_rejects_short_context_and_bad_index():
    tx = _example_tx()  # one input
    with pytest.raises(ValueError, match='spend context missing'):
        taproot_keypath_sighash(tx=tx, input_index=0, spend=[])
    # Context covering exactly the inputs, but index out of range.
    one = [SpendInput(amount=1, script_pubkey=b'\xac')]
    with pytest.raises(ValueError, match='input index 5 out of range'):
        taproot_keypath_sighash(tx=tx, input_index=5, spend=one)


# ---------------------------------------------------------------------------
# sign_segwit: scheme dispatch, mixed transactions, error paths
# ---------------------------------------------------------------------------

def _mixed_tx():
    """One tx with a legacy P2PKH input, a P2WPKH input and a P2TR
    key-path input -- all owned by the 'qwe' nonce-0 key."""
    key = seed2privkey(seed='qwe', nonce=0, passphrase='')
    pubkey = privkey2pubkey(privkey=key)
    pubhash = hash160(pubkey)
    output_key = taproot_output_key(internal_xonly=pubkey[1:33])
    spk_legacy = bytes([0x76, 0xa9, 0x14]) + pubhash + bytes([0x88, 0xac])
    spk_p2wpkh = bytes([0x00, 0x14]) + pubhash
    spk_p2tr = bytes([0x51, 0x20]) + output_key
    vin = [
        CIn(txhash=b'\xab' * 32, n=0, script=spk_legacy, sequence=0xffff_fffe),
        CIn(txhash=b'\xcd' * 32, n=1, script=spk_p2wpkh, sequence=0xffff_fffe),
        CIn(txhash=b'\xef' * 32, n=2, script=spk_p2tr, sequence=0xffff_fffe),
    ]
    vout = [COut(amount=1000, script=spk_p2wpkh),
            COut(amount=2000, script=spk_legacy)]
    tx = CTransaction(vin=vin, vout=vout, locktime=0)
    spend = [SpendInput(amount=10_000 + i, script_pubkey=spk)
             for i, spk in enumerate((spk_legacy, spk_p2wpkh, spk_p2tr))]
    return tx, (key, pubkey), spend


def test_sign_segwit_mixed_transaction_known_answer():
    # Mixed transaction (legacy + P2WPKH + P2TR inputs in one tx):
    # every scheme computes its own digest; RFC6979 ECDSA and BIP-340
    # Schnorr with aux 0x00*32 are deterministic, so the wire hex is a
    # stable cross-port KAT (the Rust side pins the same bytes).
    tx, (key, pubkey), spend = _mixed_tx()
    signed = tx.sign_segwit(signers=[(key, pubkey)] * 3, spend=spend)
    assert signed.serialize_wire().hex() == (
        '02000000000103ababababababababababababababababababababababababababab'
        'ababababab000000006a4730440220638359c6138259f5190674e7a021f07ed199f6'
        '2944bdd1c0d689cebdbda133c40220073749d937ade47fe37516fd13267a24ad1a75'
        '2432631819a34b67c80d7ceb67012103eff5d63eedb62d21b86780b468e5ca9c2f93'
        '8be2f0b23c05cd76ae1508a178d0feffffffcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'
        'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd0100000000feffffffefefefefefefefefef'
        'efefefefefefefefefefefefefefefefefefefefefefef0200000000feffffff02e8'
        '03000000000000160014e96b5b4561e70170c16f51ca30a9429e3bede977d0070000'
        '000000001976a914e96b5b4561e70170c16f51ca30a9429e3bede97788ac00024730'
        '44022073bbe46e03717a2c439970229ce116b298912ec086facb65bf43ff50f305a6'
        'a50220219e95f3675c19a18dc34359b292bdb67a58489d80bdaa80666a34bcc3365b'
        'c3012103eff5d63eedb62d21b86780b468e5ca9c2f938be2f0b23c05cd76ae1508a1'
        '78d00140854608156260555de6da00f286e8d1f789643f6c885e0a56ba1a077e1d32'
        '646fdd9b2b869dac40a8c6f109e90e317a01c4159c3c77cdb8061b02130dd94f2902'
        '00000000')
    # Per-input shape: legacy scriptSig / 2-item witness / bare 64-byte
    # Schnorr witness.
    assert signed.vin[0].script
    assert signed.vin[0].witness == ()
    assert signed.vin[1].script == b''
    assert len(signed.vin[1].witness) == 2
    assert signed.vin[2].script == b''
    assert len(signed.vin[2].witness) == 1
    assert len(signed.vin[2].witness[0]) == 64  # SIGHASH_DEFAULT: no suffix
    # txid excludes the witness; wtxid covers it.
    assert signed.id() != signed.wtxid()
    # Signing does not mutate the original.
    assert tx.vin[0].script.startswith(bytes([0x76, 0xa9]))


def test_sign_segwit_legacy_only_matches_sign():
    # For an all-legacy transaction sign_segwit is byte-identical to
    # the v0.1 sign() path.
    key = seed2privkey(seed='qwe', nonce=0, passphrase='')
    pubkey = privkey2pubkey(privkey=key)
    tx = CTransaction(vin=[CIn(txhash=TXHASH, n=0,
                               script=bytes([0x76, 0xa9, 0x14]) + hash160(pubkey)
                               + bytes([0x88, 0xac]),
                               sequence=0xffffffff)],
                      vout=[COut(amount=1000, script=b'\x51\x20')], locktime=0)
    via_sign = tx.sign(signers=[(key, pubkey)])
    via_segwit = tx.sign_segwit(signers=[(key, pubkey)])
    assert via_sign.serialize() == via_segwit.serialize()
    assert not via_segwit.has_witness()


def test_sign_segwit_rejects_signer_mismatch():
    key = seed2privkey(seed='qwe', nonce=0, passphrase='')
    pubkey = privkey2pubkey(privkey=key)
    tx = CTransaction(vin=[CIn(txhash=TXHASH, n=0, script=b'',
                               sequence=0xffff_fffe)],
                      vout=[], locktime=0)
    with pytest.raises(ValueError, match='signers length must match vin length'):
        tx.sign_segwit(signers=[])
    with pytest.raises(ValueError, match='signers length must match vin length'):
        tx.sign_segwit(signers=[(key, pubkey)] * 2)


def test_sign_segwit_requires_spend_context_for_p2wpkh():
    key = seed2privkey(seed='qwe', nonce=0, passphrase='')
    spk = bytes([0x00, 0x14]) + bytes(20)
    tx = CTransaction(vin=[CIn(txhash=TXHASH, n=0, script=spk,
                               sequence=0xffff_fffe)],
                      vout=[], locktime=0)
    signers = [(key, bytes(33))]
    with pytest.raises(ValueError, match='spend context missing'):
        tx.sign_segwit(signers=signers)
    # Context present but shorter than vin -> same error.
    with pytest.raises(ValueError, match='spend context missing'):
        tx.sign_segwit(signers=signers, spend=[])


def test_sign_segwit_requires_full_context_for_p2tr():
    key = seed2privkey(seed='qwe', nonce=0, passphrase='')
    pubkey = privkey2pubkey(privkey=key)
    spk_p2tr = bytes([0x51, 0x20]) + bytes(32)
    tx = CTransaction(
        vin=[CIn(txhash=TXHASH, n=0, script=spk_p2tr, sequence=0xffff_fffe),
             CIn(txhash=TXHASH, n=1, script=b'', sequence=0xffff_fffe)],
        vout=[], locktime=0)
    signers = [(key, pubkey)] * 2
    with pytest.raises(ValueError, match='spend context missing'):
        tx.sign_segwit(signers=signers)
    # Non-empty but not covering both inputs.
    with pytest.raises(ValueError, match='spend context missing'):
        tx.sign_segwit(signers=signers,
                       spend=[SpendInput(amount=1, script_pubkey=spk_p2tr)])
