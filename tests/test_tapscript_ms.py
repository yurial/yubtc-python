"""Tests for the Tapscript (P2TR script-path) multisig mirror of the
Rust v0.3 oracle (spec.md «Tapscript (P2TR script-path) (v0.3)»,
R-MS-7..11; mirrors `core/src/script.rs` / `address.rs` /
`transaction.rs` / `psbt.rs` / `wallet.rs` tapscript halves).

Five layers, mirroring the Rust test design (the stage-1 oracle and
its stage-2 e2e):

1. **Script vectors** (`yubtc.script`): the R-MS-7 CHECKSIGADD idiom
   builder/extractor (bounds 1/15/16 per R-MS-9, duplicates, the
   R-MS-10 x-only sort, strict shape rejections), the R-MS-11
   reverse-slot witness assembler (no dummy) and the `bc1p...`
   quorum address.
2. **Crypto vectors**: the NUMS reproduction (SHA-256 of the
   uncompressed G), leaf-hash/tweak/control-block pins verified by an
   **independent minimal-secp256k1 reference** implemented in this
   module (int math + hashlib, sharing no code with `yubtc`), the
   BIP-341 script-path sighash and the untweaked BIP-340 signer.
3. **PSBT branches**: the BIP-371 typed fields (0x14/0x15/0x17/0x18,
   0x16 preserve-only) and the p2tr arms of Creator / Signer /
   Finalizer / Extractor, per the spec's validation table.
4. **2-of-3 e2e** verified by an **independent BIP-342 stack
   evaluator** (local idiom parse, local BIP-340 verification over
   the recomputed script-path sighash -- shares no code with
   `yubtc`), with the mutation table failing: wrong slot, foreign
   signer, over-signing, empty signer slot, mutated control block.
5. **Parity fixture** (`tests/fixtures/tapscript_ms_rows.json`):
   byte-exact quorum constants, stages, witness stacks and wire hex
   generated from the Rust oracle (commit e84dfaa core; the recipe
   and generator are documented inside the fixture) -- the canonical
   source the Rust KAT regeneration consumes.
"""
import hashlib
import json
from pathlib import Path
from struct import pack

import pytest

from yubtc.crypto import (privkey2pubkey, pubkey2segwit_addr, seed2privkey,
                          tapscript_control_block, tapscript_output_key)
from yubtc.fwd import (MS_MAX_PUBKEYS, MS_TAPSCRIPT_INTERNAL_KEY,
                       PSBT_SIGHASH_ALL, PSBT_SIGHASH_DEFAULT, MsForm)
from yubtc.hash import hash160, sha256, tagged_hash
from yubtc.misc import is_dust
from yubtc.psbt import (ConflictingField, CreateInput, IncompleteInput,
                        InvalidFieldValue, InvalidKeyLength, NotFinalized,
                        PsbtTransaction, PsbtTxIn, PsbtTxOut, TapLeafScript,
                        TapScriptSig, UnknownKv, UnsupportedInputScript,
                        UnsupportedSighashType, UtxoMismatch,
                        _encode_witness_stack, _write_compact_size,
                        combine_psbt, create_psbt, extract_transaction,
                        finalize_psbt, finalize_psbt_input, parse_psbt,
                        serialize_psbt, sign_psbt_input, to_base64)
from yubtc.script import (InvalidMultisigTapscript, OP_CHECKSIG,
                          OP_CHECKSIGADD, OP_PUSHDATA1, OP_PUSHDATA2,
                          TAPSCRIPT_LEAF_VERSION, TAPSCRIPT_NUMEQUAL,
                          extract_multisig_tapscript,
                          make_multisig_tapscript,
                          make_multisig_tapscript_witness,
                          make_multisig_redeem_script, make_p2sh_lock_script,
                          make_p2tr_lock_script, make_p2wsh_lock_script,
                          make_p2wpkh_lock_script, redeem2p2sh_addr,
                          redeem2taproot_addr, tapscript_leaf_hash)
from yubtc.transaction import (SpendInput, compact_size,
                               taproot_scriptpath_sighash,
                               taproot_sign_sighash_untweaked)
from yubtc.wallet import (InvalidKeyEncoding, MS_SIG_SIZE_ESTIMATE,
                          MS_SIG_SIZE_ESTIMATE_TAP, NotAParticipant,
                          QuorumBounds, ms_create_address,
                          ms_quorum_lock_script, ms_select_utxos,
                          parse_ms_keys)


# --- Fixture family (mirrors the Rust ms fixtures) ----------------------
#
# The same (seed, own_nonce) tuples as the p2sh/p2wsh mirror: two
# seeds, cascade KDF, 2-of-3 over the seed's legacy keys at nonces
# {w, w+1, w+2}; the spend targets the seed's native-P2WPKH key at
# nonce 9. The p2tr form commits no prev tx (BIP-341 commits the
# amount through WITNESS_UTXO), so the outpoint is the synthetic
# [0x44; 32] of the Rust witness-row fixture.

SEED = 'phase15multisig'
WALLET_SEED = 'phase15wallet'
PREV_AMOUNT = 60_000
SPEND_AMOUNT = 50_000
DST_NONCE = 9

FIXTURE_PATH = Path(__file__).resolve().parent / 'fixtures' \
    / 'tapscript_ms_rows.json'


def tap_key(nonce: int, seed: str = SEED):
    """Legacy-form key at `nonce` (R-MS-6) -- the quorum member."""
    return seed2privkey(seed=seed, nonce=nonce, passphrase='', kdf='yubtc')


def tap_pub(nonce: int, seed: str = SEED) -> bytes:
    return privkey2pubkey(tap_key(nonce, seed))


def tap_keys(seed: str = SEED) -> list:
    """The full 2-of-3 quorum key set over nonces {0, 1, 2}."""
    return [tap_pub(0, seed), tap_pub(1, seed), tap_pub(2, seed)]


def tap_tapscript(seed: str = SEED) -> bytes:
    """The canonical 2-of-3 tapscript of the fixture quorum (the
    R-MS-10 x-only projections of the compressed keys)."""
    return make_multisig_tapscript(m=2,
                                   keys=[k[1:33] for k in tap_keys(seed)])


def tap_leaf_value(seed: str = SEED) -> bytes:
    """The `TAP_LEAF_SCRIPT` value: tapscript ‖ 0xc0."""
    return tap_tapscript(seed) + bytes([TAPSCRIPT_LEAF_VERSION])


def tap_spk(seed: str = SEED) -> bytes:
    """The quorum `scriptPubKey` (`51 20 ‖ x(Q)`)."""
    return ms_quorum_lock_script(redeem=tap_tapscript(seed), form=MsForm.P2TR)


def tap_control_block(seed: str = SEED) -> bytes:
    return tapscript_control_block(
        internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
        leaf_hash=tapscript_leaf_hash(script=tap_tapscript(seed)))


def tap_dst_spk(seed: str = SEED) -> bytes:
    return bytes(make_p2wpkh_lock_script(
        hash160=hash160(tap_pub(DST_NONCE, seed))))


def tap_unsigned_tx(seed: str = SEED) -> PsbtTransaction:
    """Unsigned tx spending the synthetic witness outpoint."""
    return PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x44' * 32, n=0, script=b'',
                      sequence=0xfffffffe, witness=()),),
        vout=(PsbtTxOut(amount=SPEND_AMOUNT, script=tap_dst_spk(seed)),),
        locktime=0)


def tap_create_inputs(seed: str = SEED) -> list:
    return [CreateInput(amount=PREV_AMOUNT, script_pubkey=tap_spk(seed),
                        prev_tx=None, tap_leaf_script=tap_leaf_value(seed))]


def tap_fixture_psbt(seed: str = SEED):
    """Creator + own-signer, the `ms send` shape (ОВ-12)."""
    psbt = create_psbt(unsigned_tx=tap_unsigned_tx(seed),
                       inputs=tap_create_inputs(seed))
    assert sign_psbt_input(psbt=psbt, index=0,
                           privkey=tap_key(0, seed)) is True
    return psbt


def _load_fixture() -> dict:
    with open(FIXTURE_PATH, 'r', encoding='utf-8') as fh:
        return json.load(fh)


# --- Independent minimal-secp256k1 reference (layer 1) ------------------
#
# Pure-int affine arithmetic + hashlib. Shares no code with `yubtc`
# (which uses libsecp256k1 through coincurve) -- a wrong tweak, leaf
# hash, parity bit or digest in the mirror fails against this.

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _ref_add(p1, p2):
    """Affine point addition; ``None`` is the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0]:
        if (p1[1] + p2[1]) % _P == 0:
            return None
        lam = (3 * p1[0] * p1[0]) * pow(2 * p1[1], _P - 2, _P) % _P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], _P - 2, _P) % _P
    x = (lam * lam - p1[0] - p2[0]) % _P
    return x, (lam * (p1[0] - x) - p1[1]) % _P


def _ref_mul(k, pt):
    """Double-and-add scalar multiplication."""
    out = None
    addend = pt
    while k:
        if k & 1:
            out = _ref_add(out, addend)
        addend = _ref_add(addend, addend)
        k >>= 1
    return out


def _ref_lift_x(xonly: bytes):
    """BIP-340 lift_x: the even-Y point an x-only key denotes."""
    x = int.from_bytes(xonly, 'big')
    if x >= _P:
        return None
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if (y * y) % _P != y_sq:
        return None
    if y % 2:
        y = _P - y
    return x, y


def _ref_sha256(*parts: bytes) -> bytes:
    return hashlib.sha256(b''.join(parts)).digest()


def _ref_tagged(tag: bytes, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _ref_leaf_hash(script: bytes) -> bytes:
    """hashTapLeaf per BIP-341: `0xc0 ‖ compact_size ‖ script` -- no
    0x00 prefix, minimal CompactSize."""
    n = len(script)
    if n < 0xfd:
        cs = bytes([n])
    elif n <= 0xffff:
        cs = b'\xfd' + n.to_bytes(2, 'little')
    else:
        raise AssertionError('reference covers the yubtc script sizes only')
    return _ref_tagged(b'TapLeaf', bytes([0xc0]) + cs + script)


def _ref_output_key(xonly: bytes, leaf_hash: bytes):
    """`Q = lift_x(H) + int(TapTweak(H ‖ leaf_hash))·G`:
    (x-only bytes, y parity)."""
    p = _ref_lift_x(xonly)
    assert p is not None, 'reference: internal key must lift'
    t = int.from_bytes(_ref_tagged(b'TapTweak', xonly + leaf_hash), 'big')
    assert t < _N, 'reference: tweak below the curve order'
    q = _ref_add(p, _ref_mul(t, (_GX, _GY)))
    return q[0].to_bytes(32, 'big'), q[1] & 1


def _ref_control_block(xonly: bytes, leaf_hash: bytes) -> bytes:
    out, parity = _ref_output_key(xonly, leaf_hash)
    return bytes([0xc0 | parity]) + xonly, out, parity


def _ref_sighash_fields(tx, spend) -> dict:
    """The five BIP-341 sha fields, computed from the transaction's
    raw fields with hashlib (independent of `yubtc`)."""
    prevouts = b''.join(v.txhash + pack('<L', v.n) for v in tx.vin)
    amounts = b''.join(pack('<Q', meta.amount) for meta in spend)
    spks = b''.join(bytes([len(m.script_pubkey)]) + m.script_pubkey
                    for m in spend)
    seqs = b''.join(pack('<L', v.sequence) for v in tx.vin)
    outs = b''.join(pack('<Q', o.amount) + bytes([len(o.script)]) + o.script
                    for o in tx.vout)
    return {
        'prevouts': _ref_sha256(prevouts),
        'amounts': _ref_sha256(amounts),
        'scriptpubkeys': _ref_sha256(spks),
        'sequences': _ref_sha256(seqs),
        'outputs': _ref_sha256(outs),
    }


def _ref_scriptpath_sighash(tx, index: int, spend, leaf_hash: bytes) -> bytes:
    """The BIP-341 script-path digest, from scratch: epoch 0x00 ‖
    SigMsg (hash_type 0x00, spend_type 0x02) ‖ ext (leaf_hash ‖
    key_version 0x00 ‖ codesep_pos 0xFFFFFFFF)."""
    fields = _ref_sighash_fields(tx, spend)
    sig_msg = (b'\x00'
               + pack('<l', tx.version)
               + pack('<L', tx.locktime)
               + fields['prevouts']
               + fields['amounts']
               + fields['scriptpubkeys']
               + fields['sequences']
               + fields['outputs']
               + b'\x02'
               + pack('<L', index)
               + leaf_hash
               + b'\x00'
               + pack('<L', 0xffffffff))
    return _ref_tagged(b'TapSighash', b'\x00' + sig_msg)


def _ref_bip340_verify(xonly: bytes, sig: bytes, msg: bytes) -> bool:
    """BIP-340 verification from scratch (the evaluator's primitive)."""
    if len(sig) != 64:
        return False
    p = _ref_lift_x(xonly)
    if p is None:
        return False
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    if r >= _P or s >= _N:
        return False
    e = int.from_bytes(
        _ref_tagged(b'BIP0340/challenge', sig[:32] + xonly + msg),
        'big') % _N
    point = _ref_add(_ref_mul(s, (_GX, _GY)), _ref_mul(_N - e, p))
    if point is None or point[1] & 1:
        return False
    return point[0] == r


# --- Independent BIP-342 idiom evaluator (layer 3) ----------------------


def _eval_parse_idiom(script: bytes):
    """Local strict parse of the R-MS-7 idiom: `(0x20 ‖ 32B pk ‖ op)*`
    (first op 0xac, the rest 0xba), `OP_M`, terminator; returns
    `(m, [(pk, op)])` or ``None``."""
    if len(script) < 36 or len(script) % 34 != 2:
        return None
    if script[-1] != 0x9d or not (0x51 <= script[-2] <= 0x5f):
        return None
    pairs = []
    for i in range(len(script) // 34):
        chunk = script[i * 34:(i + 1) * 34]
        if chunk[0] != 0x20:
            return None
        expected = 0xac if i == 0 else 0xba
        if chunk[33] != expected:
            return None
        pairs.append((chunk[1:33], chunk[33]))
    return script[-2] - 0x50, pairs


def _num(item: bytes) -> int:
    """The BIP-342 numeric interpretation of a stack item (CScriptNum:
    little-endian, the empty item is 0 -- sufficient for the counter
    values the idiom produces)."""
    return int.from_bytes(item, 'little')


def eval_tapscript_idiom(witness: list, sighash: bytes) -> bool:
    """Independent BIP-342 CHECKSIGADD semantics over the finalized
    stack `[w_N … w_1, script, control_block]`: each signature slot is
    verified against the script-path sighash (BIP-340), an empty slot
    contributes 0 to the accumulator, a non-empty failing signature is
    an immediate script failure, and the accumulated counter must
    equal M with exactly one truthy element left on the stack."""
    if len(witness) < 3:
        return False
    script, control_block = witness[-2], witness[-1]
    parsed = _eval_parse_idiom(script)
    if parsed is None:
        return False
    m, pairs = parsed
    # The control block must reveal this very leaf: version+parity
    # byte with the 0xc0 leaf version, the NUMS internal key, and the
    # output-key commitment to the tweaked NUMS point.
    if len(control_block) != 33 or control_block[0] & 0xfe != 0xc0:
        return False
    if control_block[1:] != bytes(MS_TAPSCRIPT_INTERNAL_KEY):
        return False
    out_key, _parity = _ref_output_key(MS_TAPSCRIPT_INTERNAL_KEY,
                                       _ref_leaf_hash(script))
    _cb_bytes, cb_out, cb_parity = _ref_control_block(
        MS_TAPSCRIPT_INTERNAL_KEY, _ref_leaf_hash(script))
    if cb_out != out_key or (control_block[0] & 1) != cb_parity:
        return False
    # Initial stack (bottom..top) = the witness slots in witness
    # order; the script then pushes each key above its slot.
    stack = list(witness[:-2])
    for i, (pk, op) in enumerate(pairs):
        stack.append(pk)
        if op == 0xac:
            pk_pop = stack.pop()
            sig = stack.pop()
            ok = bool(sig) and _ref_bip340_verify(pk_pop, sig, sighash)
            if sig and not ok:
                return False
            stack.append(b'\x01' if ok else b'')
        else:
            # BIP-342: the public key (top), the CScriptNum n (second
            # to top) and the signature (third to top) are popped.
            pk_pop = stack.pop()
            acc = _num(stack.pop())
            sig = stack.pop()
            ok = bool(sig) and _ref_bip340_verify(pk_pop, sig, sighash)
            if sig and not ok:
                return False
            stack.append(bytes([acc + (1 if ok else 0)]))
    stack.append(bytes([m]))
    numeq = _num(stack.pop())
    counter = _num(stack.pop())
    stack.append(b'\x01' if counter == numeq else b'')
    return len(stack) == 1 and stack[0] == b'\x01'


# --- 1. Constants, NUMS, R-MS-9 bounds -----------------------------------


def test_fwd_pins_the_tapscript_constants():
    from yubtc.fwd import MS_FORMS
    assert MS_TAPSCRIPT_INTERNAL_KEY == bytes.fromhex(
        '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')
    assert MS_FORMS == (MsForm.P2SH, MsForm.P2WSH, MsForm.P2TR)
    assert MS_SIG_SIZE_ESTIMATE_TAP == 66
    # The ECDSA estimate stays untouched (the CHECKMULTISIG forms).
    assert MS_SIG_SIZE_ESTIMATE == 73
    assert TAPSCRIPT_LEAF_VERSION == 0xc0
    assert OP_CHECKSIGADD == 0xba
    assert OP_CHECKSIG == 0xac
    # The idiom terminator byte: the oracle's OP_NUMEQUAL spelling.
    assert TAPSCRIPT_NUMEQUAL == 0x9d


def test_nums_reproduces_sha256_of_uncompressed_g():
    """R-MS-8/ОВ-15: the NUMS x-coordinate is SHA-256 of the
    *uncompressed* encoding of G (the BIP-341 text value)."""
    uncompressed = b'\x04' + _GX.to_bytes(32, 'big') + _GY.to_bytes(32, 'big')
    assert _ref_sha256(uncompressed) == MS_TAPSCRIPT_INTERNAL_KEY
    # And the fixture pins the same reproduction from the oracle side.
    pins = _load_fixture()['pins']
    assert pins['nums_hex'] == MS_TAPSCRIPT_INTERNAL_KEY.hex()
    assert pins['nums_is_sha256_of_uncompressed_g_hex'] \
        == MS_TAPSCRIPT_INTERNAL_KEY.hex()


def test_rms9_const_guard_and_n15_script():
    """R-MS-9: the unified bound is the 520-byte element limit --
    34·15 + 2 = 512 ≤ 520 < 546 = 34·16 + 2."""
    assert 34 * MS_MAX_PUBKEYS + 2 == 512
    assert 34 * (MS_MAX_PUBKEYS + 1) + 2 == 546
    assert 512 <= 520 < 546
    pins = _load_fixture()['pins']
    assert pins['script_size_at_15'] == 512
    assert pins['script_size_at_16'] == 546
    assert pins['max_script_element_size'] == 520
    # The N = 15 leaf is a valid 512-byte script.
    keys_15 = sorted(tap_pub(n)[1:33] for n in range(15))
    script = make_multisig_tapscript(m=15, keys=keys_15)
    assert len(script) == 512
    m, keys = extract_multisig_tapscript(script=script)
    assert (m, keys) == (15, keys_15)


def test_builder_n16_and_other_bounds_refused():
    keys_16 = [tap_pub(n) for n in range(16)]
    with pytest.raises(InvalidMultisigTapscript):
        make_multisig_tapscript(m=16, keys=keys_16)
    with pytest.raises(InvalidMultisigTapscript):
        make_multisig_tapscript(m=0, keys=keys_16[:2])
    with pytest.raises(InvalidMultisigTapscript):
        make_multisig_tapscript(m=3, keys=keys_16[:2])
    with pytest.raises(InvalidMultisigTapscript):
        make_multisig_tapscript(m=1, keys=[])
    # The runtime equivalent of the Rust `[[u8; 32]]` parameter type.
    with pytest.raises(InvalidMultisigTapscript):
        make_multisig_tapscript(m=1, keys=[tap_pub(0)[2:]])
    with pytest.raises(InvalidMultisigTapscript):
        make_multisig_tapscript(m=1, keys=[tap_pub(0), tap_pub(0)])


def test_builder_is_invariant_under_argument_order():
    """R-MS-4/R-MS-10: the same key set always yields the same script
    (the fixture quorum in every rotation)."""
    base = tap_tapscript()
    for perm in ([0, 1, 2], [2, 1, 0], [1, 0, 2], [2, 0, 1]):
        assert make_multisig_tapscript(
            m=2, keys=[tap_pub(n)[1:33] for n in perm]) == base
    assert extract_multisig_tapscript(script=base)[1] \
        == sorted(k[1:33] for k in tap_keys())


# --- 2. Script vectors: the R-MS-7 idiom ---------------------------------


def test_idiom_wire_layout_pins():
    """The canonical byte layout: `0x20 ‖ pk OP_CHECKSIG, 0x20 ‖ pk
    OP_CHECKSIGADD …, OP_M, terminator` -- size 34N + 2."""
    script = tap_tapscript()
    keys_sorted = sorted(k[1:33] for k in tap_keys())
    expected = bytearray()
    for i, key in enumerate(keys_sorted):
        expected.append(0x20)
        expected += key
        expected.append(OP_CHECKSIG if i == 0 else OP_CHECKSIGADD)
    expected.append(0x52)  # OP_2
    expected.append(TAPSCRIPT_NUMEQUAL)
    assert script == bytes(expected)
    assert len(script) == 34 * 3 + 2
    # The minimal 1-of-1 leaf.
    one = make_multisig_tapscript(m=1, keys=[tap_pub(0)[1:33]])
    assert one == (b'\x20' + tap_pub(0)[1:33] + bytes([OP_CHECKSIG, 0x51])
                   + bytes([TAPSCRIPT_NUMEQUAL]))
    assert len(one) == 36
    # The 2-of-2 script of the fixture's script_table.
    entry = next(e for e in _load_fixture()['script_table']
                 if e['m'] == 2 and e['n'] == 2)
    keys = [bytes.fromhex(h) for h in entry['keys_hex']]
    assert make_multisig_tapscript(m=2, keys=keys) \
        == bytes.fromhex(entry['script_hex'])


def test_extractor_round_trip_table():
    """Builder ↔ extractor round-trips for the fixture quorum table
    (all entries: m ≤ n ≤ 15)."""
    for entry in _load_fixture()['script_table']:
        script = bytes.fromhex(entry['script_hex'])
        m, keys = extract_multisig_tapscript(script=script)
        assert m == entry['m']
        assert len(keys) == entry['n']
        # The extractor reports script order (the R-MS-10 x-only
        # sort); `keys_hex` is the entry's scrambled input order.
        assert keys == sorted(bytes.fromhex(h)
                              for h in entry['keys_hex'])
        # Round-trip: re-building from the extracted keys is stable.
        assert make_multisig_tapscript(m=m, keys=keys) == script


def test_extractor_rejections():
    """Strict shape check: PUSHDATA wrappers, compressed-key pushes,
    CHECKMULTISIG byte, the 0x9c byte in place of the terminator,
    wrong opcodes, trailing bytes, truncated scripts, duplicates,
    bound violations."""
    good = tap_tapscript()

    def mutated(script: bytes) -> bytes:
        extract_multisig_tapscript(script=good)  # sanity: base is canonical
        return script

    # Truncated: below the 36-byte minimum.
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(good[:-1]))
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(b''))
    # Wrong terminator byte (0x9c where the idiom demands 0x9d).
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(good[:-1] + b'\x9c'))
    # CHECKMULTISIG (0xae) as the terminus: the disabled opcode.
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(good[:-2] + b'\x01\xae'))
    # OP_M out of range: 0x50 and 0x60.
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(good[:-2] + b'\x50\x9d'))
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(good[:-2] + b'\x60\x9d'))
    # m > n: OP_4 over a 3-key body.
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(good[:-2] + b'\x54\x9d'))
    # A trailing fragment shifts the frame (body % 34 != 0).
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(good + b'\x00'))
    # OP_PUSHDATA-wrapped key: the 34-byte frame breaks.
    key = sorted(k[1:33] for k in tap_keys())[0]
    pushdata_key = bytes([OP_PUSHDATA1, 32]) + key
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(
            pushdata_key + good[33:]))
    # A 33-byte compressed push (0x21) is not an x-only key.
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(
            b'\x21' + tap_pub(0) + good[34:]))
    # A 0x20 push whose opcode is wrong: CHECKSIGADD first,
    # CHECKSIG second.
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(
            b'\x20' + key + bytes([OP_CHECKSIGADD]) + good[34:]))
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(
            good[:34] + b'\x20' + key + bytes([OP_CHECKSIG])
            + good[68:-2]))
    # Duplicate keys (degenerate quorum): the builder refuses them,
    # so the duplicated script is assembled by hand.
    key = sorted(k[1:33] for k in tap_keys())[0]
    dup = (b'\x20' + key + bytes([OP_CHECKSIG])
           + b'\x20' + key + bytes([OP_CHECKSIGADD])
           + bytes([0x52]) + bytes([TAPSCRIPT_NUMEQUAL]))
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=mutated(dup))
    with pytest.raises(InvalidMultisigTapscript):
        make_multisig_tapscript(m=2, keys=[key, key])
    # N = 16 (546 bytes): the physical R-MS-9 refusal.
    keys_16 = sorted(tap_pub(n)[1:33] for n in range(16))
    body = b''.join(b'\x20' + k + (bytes([OP_CHECKSIG]) if i == 0
                                   else bytes([OP_CHECKSIGADD]))
                    for i, k in enumerate(keys_16))
    with pytest.raises(InvalidMultisigTapscript):
        extract_multisig_tapscript(script=body + b'\x51\x9d')


def test_sort_divergence_x_only_vs_compressed():
    """R-MS-10: p2tr sorts by the 32 x-only bytes -- the fixture's
    divergence pair (compressed prefix 03/02) orders *opposite* to a
    BIP-67 compressed sort, and the oracle script keeps the x-only
    order."""
    pin = _load_fixture()['sort_divergence_pin']
    k_comp = bytes.fromhex(pin['k_compressed_hex'])
    l_comp = bytes.fromhex(pin['l_compressed_hex'])
    # The compressed encodings sort the other way...
    assert sorted([k_comp, l_comp]) == [l_comp, k_comp]
    # ...but the tapscript carries the x-only order.
    script = make_multisig_tapscript(
        m=2, keys=[k_comp[1:33], l_comp[1:33]])
    assert script == bytes.fromhex(pin['script_hex'])
    assert extract_multisig_tapscript(script=script)[1] \
        == [k_comp[1:33], l_comp[1:33]]
    # Reversed input order: same script.
    assert make_multisig_tapscript(
        m=2, keys=[l_comp[1:33], k_comp[1:33]]) == script


# --- 3. Crypto vectors: leaf hash, tweak, control block, address --------


def test_leaf_hash_structure_and_no_dummy_prefix():
    """hashTapLeaf = tagged_hash('TapLeaf', 0xc0 ‖ compact_size ‖
    script): no 0x00 prefix, minimal CompactSize (512 → fd 00 02)."""
    script = tap_tapscript()
    ref = _ref_leaf_hash(script)
    assert tapscript_leaf_hash(script=script) == ref
    # A 0x00 prefix (the BIP-342 leaf-variant spelling) must NOT be
    # part of the preimage.
    wrong = tagged_hash(b'TapLeaf', b'\x00\xc0' + compact_size(len(script))
                        + script)
    assert wrong != ref
    # The maximal script pins the minimal CompactSize encoding.
    keys_15 = sorted(tap_pub(n)[1:33] for n in range(15))
    script_15 = make_multisig_tapscript(m=15, keys=keys_15)
    assert tapscript_leaf_hash(script=script_15) == _ref_leaf_hash(script_15)
    # Explicitly: the encoding is fd 00 02, not an OP_PUSHDATA push.
    assert len(script_15) == 512
    msg = b'\xc0' + b'\xfd\x00\x02' + script_15
    assert tagged_hash(b'TapLeaf', msg) \
        == tapscript_leaf_hash(script=script_15)
    push_style = b'\xc0' + bytes([OP_PUSHDATA2]) + (512).to_bytes(2, 'little') \
        + script_15
    assert tagged_hash(b'TapLeaf', push_style) \
        != tapscript_leaf_hash(script=script_15)


def test_output_key_and_control_block_match_reference():
    """tapscript_output_key / tapscript_control_block against the
    independent reference -- for every fixture script_table entry and
    the pipeline quorum."""
    nums = MS_TAPSCRIPT_INTERNAL_KEY
    for entry in _load_fixture()['script_table']:
        script = bytes.fromhex(entry['script_hex'])
        leaf_hash = tapscript_leaf_hash(script=script)
        assert leaf_hash == bytes.fromhex(entry['leaf_hash_hex'])
        ref_cb, ref_out, ref_parity = _ref_control_block(nums, leaf_hash)
        out = tapscript_output_key(internal_xonly=nums, leaf_hash=leaf_hash)
        cb = tapscript_control_block(internal_xonly=nums,
                                     leaf_hash=leaf_hash)
        assert out == ref_out == bytes.fromhex(entry['output_key_hex'])
        assert cb == ref_cb == bytes.fromhex(entry['control_hex'])
        assert len(cb) == 33
        assert cb[0] & 0xfe == 0xc0
        assert cb[0] & 1 == ref_parity
        assert cb[1:] == nums


def test_quorum_address_round_trip_and_pins():
    from yubtc.crypto import decode_taproot_addr
    script = tap_tapscript()
    addr = redeem2taproot_addr(script=script)
    assert len(addr) == 62
    assert addr.startswith('bc1p')
    wp = decode_taproot_addr(address=addr)
    assert (wp.version, wp.program) == (1, tapscript_output_key(
        internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
        leaf_hash=tapscript_leaf_hash(script=script)))
    assert bytes(make_p2tr_lock_script(output_key=wp.program)) == tap_spk()
    # The fixture quorum constants (anchor row).
    row = _load_fixture()['rows'][0]
    assert redeem2taproot_addr(
        script=bytes.fromhex(row['redeem_hex'])) == row['address']
    assert tap_spk().hex() == row['script_pubkey_hex']
    # One quorum, three addresses: the p2sh/p2wsh redeems differ from
    # the tapscript bytes.
    p2sh_addr, p2sh_redeem = ms_create_address(
        n=3, m=2, keys=tap_keys(), form=MsForm.P2SH)
    assert p2sh_redeem != script
    assert p2sh_addr.startswith('3')
    assert redeem2p2sh_addr(redeem=p2sh_redeem) == p2sh_addr


def test_tapscript_output_key_argument_checks():
    nums = MS_TAPSCRIPT_INTERNAL_KEY
    leaf = tapscript_leaf_hash(script=tap_tapscript())
    with pytest.raises(ValueError, match='internal pubkey must be 32 bytes'):
        tapscript_output_key(internal_xonly=nums[:31], leaf_hash=leaf)
    with pytest.raises(ValueError, match='leaf hash must be 32 bytes'):
        tapscript_output_key(internal_xonly=nums, leaf_hash=leaf[:31])
    with pytest.raises(ValueError, match='internal pubkey must be 32 bytes'):
        tapscript_control_block(internal_xonly=nums[:31], leaf_hash=leaf)
    with pytest.raises(ValueError, match='leaf hash must be 32 bytes'):
        tapscript_control_block(internal_xonly=nums, leaf_hash=b'')
    # A non-curve point is a typed failure (lift_x per BIP-340).
    from yubtc.crypto import TapTweakError
    bad_point = (2 ** 256 - 1).to_bytes(32, 'big')
    with pytest.raises(TapTweakError, match='not a valid curve point'):
        tapscript_output_key(internal_xonly=bad_point, leaf_hash=leaf)
    with pytest.raises(TapTweakError, match='not a valid curve point'):
        tapscript_control_block(internal_xonly=bad_point, leaf_hash=leaf)


def test_tweak_script_scalar_rejects_t_at_or_above_order():
    """BIP-341 MUST-fail: the script-path tweak refuses `t ≥ n`
    (the ~2^-128 case, exercised through the crafted-digest split)."""
    from yubtc.crypto import TapTweakError, _tweak_script_scalar_from_digest
    with pytest.raises(TapTweakError, match='curve order'):
        _tweak_script_scalar_from_digest(b'\xff' * 32)
    # Exactly the order is refused too; a value below it passes.
    from yubtc.bip32 import SECP256K1_N
    with pytest.raises(TapTweakError):
        _tweak_script_scalar_from_digest(SECP256K1_N.to_bytes(32, 'big'))
    assert _tweak_script_scalar_from_digest(
        (SECP256K1_N - 1).to_bytes(32, 'big')) == SECP256K1_N - 1


def test_control_block_infinity_is_typed(monkeypatch):
    """The `Q = ∞` branch (p ~ 2^-128) is reachable only through a
    crafted tweak scalar: with `internal = -5G` (parity-flipped 5G)
    and the crafted scalar 5, `P + t·G` is the point at infinity."""
    import yubtc.crypto
    from yubtc.crypto import TapTweakError
    # A base point whose x-only lift is the *odd*-parity representative
    # would need y(kG) odd: then lift_x picks -kG (even y) and the
    # crafted scalar k sends Q to infinity.
    k = next(k for k in range(1, 20)
             if _ref_mul(k, (_GX, _GY))[1] & 1)
    xonly = _ref_mul(k, (_GX, _GY))[0].to_bytes(32, 'big')
    monkeypatch.setattr(
        yubtc.crypto, '_tweak_script_scalar_from_digest',
        lambda t_bytes: k)
    with pytest.raises(TapTweakError, match='point at infinity'):
        tapscript_control_block(internal_xonly=xonly,
                                leaf_hash=b'\x11' * 32)


# --- 4. Digest + signer: BIP-341 script path, untweaked BIP-340 --------


def test_scriptpath_sighash_matches_reference_and_oracle_pin():
    """The mirror's BIP-341 script-path digest equals the from-scratch
    reference (and the anchor row's oracle sighash); malformed
    contexts/indexes raise ValueError."""
    tx = tap_unsigned_tx()
    spend = [SpendInput(amount=PREV_AMOUNT, script_pubkey=tap_spk())]
    leaf = tapscript_leaf_hash(script=tap_tapscript())
    got = taproot_scriptpath_sighash(tx=tx, input_index=0, spend=spend,
                                     leaf_hash=leaf)
    assert got == _ref_scriptpath_sighash(tx, 0, spend, leaf)
    # The oracle anchor row pins the very digest the own signer used.
    assert got == bytes.fromhex(_load_fixture()['rows'][0]['sighash_hex'])
    # Context must cover every input; index must be in range.
    with pytest.raises(ValueError, match='spend context'):
        taproot_scriptpath_sighash(tx=tx, input_index=0, spend=[],
                                   leaf_hash=leaf)
    with pytest.raises(ValueError, match='out of range'):
        taproot_scriptpath_sighash(tx=tx, input_index=5, spend=spend,
                                   leaf_hash=leaf)


def test_untweaked_signer_verifies_and_matches_oracle_pin():
    """The script-path signer is *untweaked* BIP-340: the signature
    verifies under the script's x-only key against the script-path
    digest, is deterministic, and equals the oracle anchor row's
    signature; the key-path (tweaked) signer differs."""
    sighash = bytes.fromhex(_load_fixture()['rows'][0]['sighash_hex'])
    sig = taproot_sign_sighash_untweaked(privkey=tap_key(0),
                                         sighash=sighash)
    assert len(sig) == 64
    assert sig == bytes.fromhex(_load_fixture()['rows'][0]['own_sig_hex'])
    assert _ref_bip340_verify(tap_pub(0)[1:33], sig, sighash)
    assert taproot_sign_sighash_untweaked(privkey=tap_key(0),
                                          sighash=sighash) == sig
    from yubtc.transaction import taproot_sign_sighash
    assert taproot_sign_sighash(privkey=tap_key(0), sighash=sighash) != sig


# --- 5. The R-MS-11 witness assembler ------------------------------------


def test_witness_assembler_reverses_slots_and_has_no_dummy():
    """R-MS-11: `[w_N … w_1] ‖ script ‖ control_block` -- slots
    reverse, non-signers ride as empty items, and there is no
    CHECKMULTISIG dummy."""
    script = tap_tapscript()
    control = tap_control_block()
    s1, s3 = b'\x01' * 64, b'\x03' * 64
    stack = make_multisig_tapscript_witness(
        script=script, control_block=control, sig_slots=[s1, None, s3])
    assert stack == [s3, b'', s1, script, control]
    # All-empty: still exactly N + 2 items, no dummy, no count check
    # (that is the Finalizer's job).
    empty = make_multisig_tapscript_witness(
        script=script, control_block=control,
        sig_slots=[None, None, None])
    assert empty == [b'', b'', b'', script, control]


# --- 6. PSBT: BIP-371 typed fields (0x14/0x15/0x17/0x18, 0x16 opaque) ----
#
# Raw-map helpers (mirroring test_psbt.py's assembler): a stub unsigned
# tx plus hand-written per-input maps exercise the parser/serializer
# branches directly.

def _raw_kv(key: bytes, value: bytes) -> bytes:
    out = bytearray()
    _write_compact_size(out, len(key))
    out += key
    _write_compact_size(out, len(value))
    out += value
    return bytes(out)


def _raw_assemble(global_pairs: list, input_maps: list) -> bytes:
    out = bytearray(b'\x70\x73\x62\x74\xff')
    for pair in global_pairs:
        out += pair
    out.append(0)
    for m in input_maps:
        out += m
        out.append(0)
    out.append(0)  # the single output map (matching the stub tx)
    return bytes(out)


def _stub_tx_bytes() -> bytes:
    """A minimal valid unsigned tx (one input, one OP_1 output)."""
    out = bytearray()
    out += pack('<l', 2)
    out.append(1)  # one vin
    out += b'\x11' * 32
    out += pack('<L', 1)
    out.append(0)  # empty scriptSig
    out += pack('<L', 0xffffffff)
    out.append(1)  # one vout
    out += pack('<Q', 1000)
    out.append(1)
    out.append(0x51)
    out += pack('<L', 0)
    return bytes(out)


def _wire_psbt(input_map: bytes) -> bytes:
    return _raw_assemble([_raw_kv(b'\x00', _stub_tx_bytes())],
                         [input_map])


def _witness_utxo_value(amount: int, script: bytes) -> bytes:
    value = bytearray()
    value += pack('<Q', amount)
    _write_compact_size(value, len(script))
    value += script
    return bytes(value)


def _input_map(*pairs: tuple) -> bytes:
    out = b''
    for key, value in pairs:
        out += _raw_kv(key, value)
    return out


def _parse_one(input_map: bytes):
    return parse_psbt(data=_raw_assemble(
        [_raw_kv(b'\x00', _stub_tx_bytes())], [input_map]))


def _bip371_base_pairs():
    """The common field set of the raw-map tests: a P2TR WITNESS_UTXO
    paying to the fixture quorum."""
    return [(b'\x01', _witness_utxo_value(PREV_AMOUNT, tap_spk()))]


def test_psbt_parser_accepts_bip371_fields():
    control = tap_control_block()
    leaf_value = tap_leaf_value()
    internal = bytes(MS_TAPSCRIPT_INTERNAL_KEY)
    root = tapscript_leaf_hash(script=tap_tapscript())
    sig = b'\x22' * 64
    psbt = _parse_one(_input_map(
        *(_bip371_base_pairs()
          + [(b'\x14' + tap_pub(0)[1:33] + root, sig),
             (b'\x15' + control, leaf_value),
             (b'\x17', internal),
             (b'\x18', root)])))
    input_ = psbt.inputs[0]
    assert input_.tap_script_sigs == [TapScriptSig(
        x_only=tap_pub(0)[1:33], leaf_hash=root, sig=sig)]
    assert input_.tap_leaf_scripts == [TapLeafScript(
        control_block=control, script_with_version=leaf_value)]
    assert input_.tap_internal_key == internal
    assert input_.tap_merkle_root == root
    assert input_.unknown == []
    # Round-trip: the serializer writes the same typed pairs back.
    again = parse_psbt(data=serialize_psbt(psbt=psbt))
    assert serialize_psbt(psbt=again) == serialize_psbt(psbt=psbt)
    raw = serialize_psbt(psbt=psbt)
    assert _raw_kv(b'\x14' + tap_pub(0)[1:33] + root, sig) in raw
    assert _raw_kv(b'\x15' + control, leaf_value) in raw
    assert _raw_kv(b'\x17', internal) in raw
    assert _raw_kv(b'\x18', root) in raw


def test_psbt_parser_bip371_error_arms():
    """The typed-parser refusals: wrong keydata lengths and malformed
    values map to the BIP-174 field errors, never a crash."""
    good_value = tap_leaf_value()
    bad_maps = [
        # 0x14: the key is x-only ‖ leaf_hash -- exactly 64 bytes.
        [(b'\x14', b'\x22' * 64), (b'\x01',
                                   _witness_utxo_value(1, tap_spk()))],
        [(b'\x14' + b'\x10' * 63, b'\x22' * 64),
         (b'\x01', _witness_utxo_value(1, tap_spk()))],
        # 0x15: the key is the 33-byte control block, the value the
        # non-empty script ‖ 0xc0.
        [(b'\x15' + b'\x10' * 32, good_value),
         (b'\x01', _witness_utxo_value(1, tap_spk()))],
        [(b'\x15' + tap_control_block(), b''),
         (b'\x01', _witness_utxo_value(1, tap_spk()))],
        # 0x17: empty keydata, exactly 32 value bytes.
        [(b'\x17' + b'\x01', b'\x10' * 32),
         (b'\x01', _witness_utxo_value(1, tap_spk()))],
        [(b'\x17', b'\x10' * 31),
         (b'\x01', _witness_utxo_value(1, tap_spk()))],
        # 0x18: empty keydata, exactly 32 value bytes (read-only).
        [(b'\x18' + b'\x01', b'\x10' * 32),
         (b'\x01', _witness_utxo_value(1, tap_spk()))],
        [(b'\x18', b'\x10' * 31),
         (b'\x01', _witness_utxo_value(1, tap_spk()))],
    ]
    for pairs in bad_maps:
        with pytest.raises((InvalidKeyLength, InvalidFieldValue)):
            _parse_one(_input_map(*pairs))


def test_psbt_0x16_tap_bip32_derivation_is_opaque_passthrough():
    """ОВ-18: `TAP_BIP32_DERIVATION (0x16)` is not in the typed
    registry -- the parser parks it in `unknown`, the serializer
    writes it back byte-for-byte, and the Combiner treats it like any
    opaque pair (equal merges, different values conflict)."""
    key = b'\x16' + tap_pub(1)[1:33]
    value = b'\x22' * 33
    psbt = _parse_one(_input_map(*(_bip371_base_pairs() + [(key, value)])))
    assert psbt.inputs[0].unknown == [UnknownKv(key=key, value=value)]
    assert _raw_kv(key, value) in serialize_psbt(psbt=psbt)
    other = _parse_one(_input_map(*(_bip371_base_pairs()
                                    + [(key, value)])))
    merged = combine_psbt(psbt=psbt, other=other)
    assert merged.inputs[0].unknown == [UnknownKv(key=key, value=value)]
    conflicting = _parse_one(_input_map(
        *(_bip371_base_pairs() + [(key, b'\x33' * 33)])))
    with pytest.raises(ConflictingField):
        combine_psbt(psbt=psbt, other=conflicting)


def test_psbt_combine_merges_taproot_fields():
    """The Combiner carries the typed taproot lists: disjoint
    `TAP_SCRIPT_SIG` entries union and sort by `(x_only, leaf_hash)`;
    identical `TAP_LEAF_SCRIPT`/`TAP_INTERNAL_KEY` collapse; a
    conflicting same-key signature value is a deterministic
    `ConflictingField`."""
    psbt = tap_fixture_psbt()  # own key (nonce 0) already signed
    other = create_psbt(unsigned_tx=tap_unsigned_tx(),
                        inputs=tap_create_inputs())
    assert sign_psbt_input(psbt=other, index=0, privkey=tap_key(1))
    merged = combine_psbt(psbt=psbt, other=other)
    sigs = merged.inputs[0].tap_script_sigs
    assert len(sigs) == 2
    assert sigs == sorted(sigs)
    assert [s.x_only for s in sigs] \
        == sorted(k[1:33] for k in (tap_pub(0), tap_pub(1)))
    # The same two signatures in insertion-order-swapped containers
    # merge to the byte-identical container (Combiner commutativity).
    swapped = combine_psbt(psbt=other, other=psbt)
    assert to_base64(psbt=swapped) == to_base64(psbt=merged)
    # Conflicting value under the same (x_only, leaf_hash) key: two
    # containers signed by the *same* member, one value corrupted.
    left = tap_fixture_psbt()
    right = tap_fixture_psbt()
    right.inputs[0].tap_script_sigs[0] \
        = right.inputs[0].tap_script_sigs[0]._replace(sig=b'\x11' * 64)
    with pytest.raises(ConflictingField):
        combine_psbt(psbt=left, other=right)


def test_psbt_combine_conflicting_leaf_and_internal_key():
    """Equal control-block keys with different leaf values (and equal
    `TAP_INTERNAL_KEY`s with different values) are
    `ConflictingField`; equal ones collapse."""
    base = create_psbt(unsigned_tx=tap_unsigned_tx(),
                       inputs=tap_create_inputs())
    other = create_psbt(unsigned_tx=tap_unsigned_tx(),
                        inputs=tap_create_inputs())
    other.inputs[0].tap_leaf_scripts[0] = TapLeafScript(
        control_block=tap_control_block(),
        script_with_version=tap_leaf_value()[:-1] + b'\xc1')
    with pytest.raises(ConflictingField):
        combine_psbt(psbt=base, other=other)
    other2 = create_psbt(unsigned_tx=tap_unsigned_tx(),
                         inputs=tap_create_inputs())
    other2.inputs[0].tap_internal_key = b'\x33' * 32
    with pytest.raises(ConflictingField):
        combine_psbt(psbt=base, other=other2)
    # Equal values collapse (idempotent combine).
    again = combine_psbt(psbt=base, other=base)
    assert to_base64(psbt=again) == to_base64(psbt=base)


# --- 7. PSBT: the p2tr Creator / Signer / Finalizer / Extractor ----------


def test_creator_p2tr_branch_writes_tap_fields_and_witness_utxo():
    """The Creator p2tr branch: `WITNESS_UTXO` (no prev tx fetch),
    `TAP_LEAF_SCRIPT` keyed by the derived 33-byte control block, and
    `TAP_INTERNAL_KEY` = NUMS; no redeem/witness script."""
    psbt = create_psbt(unsigned_tx=tap_unsigned_tx(),
                       inputs=tap_create_inputs())
    input_ = psbt.inputs[0]
    assert input_.non_witness_utxo is None
    assert input_.witness_utxo is not None
    assert input_.witness_utxo.amount == PREV_AMOUNT
    assert input_.witness_utxo.script == tap_spk()
    assert input_.redeem_script is None
    assert input_.witness_script is None
    assert input_.tap_leaf_scripts == [TapLeafScript(
        control_block=tap_control_block(),
        script_with_version=tap_leaf_value())]
    assert input_.tap_internal_key == bytes(MS_TAPSCRIPT_INTERNAL_KEY)


def test_creator_tap_leaf_on_a_foreign_input_falls_through():
    """A `tap_leaf_script` on a non-P2TR input is not a Creator
    surface yubtc builds: the field is dropped and the input lands in
    the default `WITNESS_UTXO` arm (preserve-only for foreign
    forms)."""
    odd = b'\x6a' + b'\x07' * 9
    psbt = create_psbt(unsigned_tx=tap_unsigned_tx(),
                       inputs=[CreateInput(amount=PREV_AMOUNT,
                                           script_pubkey=odd,
                                           prev_tx=None,
                                           tap_leaf_script=tap_leaf_value())])
    input_ = psbt.inputs[0]
    assert input_.witness_utxo is not None
    assert input_.witness_utxo.script == odd
    assert input_.tap_leaf_scripts == []
    assert input_.tap_internal_key is None


def test_creator_p2tr_branch_rejections():
    """A tap leaf that is not the canonical 0xc0-terminated R-MS-7
    script, or whose tweaked NUMS output key does not commit to the
    UTXO program, is refused (`UnsupportedInputScript` /
    `UtxoMismatch`)."""
    empty_value = b''
    with pytest.raises(UnsupportedInputScript):
        create_psbt(unsigned_tx=tap_unsigned_tx(),
                    inputs=[CreateInput(amount=PREV_AMOUNT,
                                        script_pubkey=tap_spk(),
                                        prev_tx=None,
                                        tap_leaf_script=empty_value)])
    bad_version = tap_tapscript() + b'\xc1'
    with pytest.raises(UnsupportedInputScript):
        create_psbt(unsigned_tx=tap_unsigned_tx(),
                    inputs=[CreateInput(amount=PREV_AMOUNT,
                                        script_pubkey=tap_spk(),
                                        prev_tx=None,
                                        tap_leaf_script=bad_version)])
    non_canonical = tap_leaf_value()[:-1] + b'\x00' + b'\xc0'
    with pytest.raises(UnsupportedInputScript):
        create_psbt(unsigned_tx=tap_unsigned_tx(),
                    inputs=[CreateInput(amount=PREV_AMOUNT,
                                        script_pubkey=tap_spk(),
                                        prev_tx=None,
                                        tap_leaf_script=non_canonical)])
    # A foreign P2TR program: the leaf commits elsewhere.
    foreign_spk = bytes(make_p2tr_lock_script(
        output_key=tapscript_output_key(
            internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
            leaf_hash=tagged_hash(b'other', b''))))
    with pytest.raises(UtxoMismatch):
        create_psbt(unsigned_tx=tap_unsigned_tx(),
                    inputs=[CreateInput(amount=PREV_AMOUNT,
                                        script_pubkey=foreign_spk,
                                        prev_tx=None,
                                        tap_leaf_script=tap_leaf_value())])


def _signer_psbt():
    psbt = create_psbt(unsigned_tx=tap_unsigned_tx(),
                       inputs=tap_create_inputs())
    return psbt


def test_signer_p2tr_scriptpath_signs_own_key():
    """The Signer p2tr arm: membership (not scriptPubKey ownership)
    signs the script-path digest with the untweaked key into a
    64-byte `TAP_SCRIPT_SIG` keyed by `x_only ‖ leaf_hash`."""
    psbt = _signer_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(1)) is True
    leaf = tapscript_leaf_hash(script=tap_tapscript())
    (entry,) = psbt.inputs[0].tap_script_sigs
    assert entry.x_only == tap_pub(1)[1:33]
    assert entry.leaf_hash == leaf
    assert len(entry.sig) == 64
    # Idempotent: a second pass adds nothing.
    assert sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(1)) is True
    assert len(psbt.inputs[0].tap_script_sigs) == 1


def test_signer_p2tr_scriptpath_foreign_key_is_skipped():
    """A non-member key is not an error: the Signer reports False."""
    from yubtc.crypto import seed2privkey
    stranger = seed2privkey(seed='a stranger seed', nonce=0,
                            passphrase='', kdf='yubtc')
    assert sign_psbt_input(psbt=_signer_psbt(), index=0,
                           privkey=stranger) is False


def test_signer_p2tr_scriptpath_rejections():
    """The Signer's structural/commitment ladder: foreign control
    blocks and leaves are `UnsupportedInputScript`; a commitment
    mismatch is `UtxoMismatch`; a pinned non-default sighash is
    `UnsupportedSighashType`; a present-but-wrong `NON_WITNESS_UTXO`
    is `UtxoMismatch`."""
    leaf = tapscript_leaf_hash(script=tap_tapscript())

    def with_leaf(control_block=None, leaf_value=None):
        psbt = create_psbt(unsigned_tx=tap_unsigned_tx(),
                           inputs=tap_create_inputs())
        if control_block is not None:
            psbt.inputs[0].tap_leaf_scripts[0] = TapLeafScript(
                control_block=control_block,
                script_with_version=psbt.inputs[0]
                .tap_leaf_scripts[0].script_with_version)
        if leaf_value is not None:
            psbt.inputs[0].tap_leaf_scripts[0] = TapLeafScript(
                control_block=psbt.inputs[0]
                .tap_leaf_scripts[0].control_block,
                script_with_version=leaf_value)
        return psbt

    # Control block: 33 bytes, 0xc0 leaf version, NUMS internal key.
    for control in (b'\xc0' + b'\x10' * 31,  # 32 bytes
                    b'\xbf' + tap_control_block()[1:],  # version bits
                    b'\xc0' + b'\x33' * 32):  # foreign internal key
        with pytest.raises(UnsupportedInputScript):
            sign_psbt_input(psbt=with_leaf(control_block=control),
                            index=0, privkey=tap_key(0))
    # Leaf value: the version byte is exactly 0xc0, and the script
    # must pass the strict R-MS-7 shape check.
    with pytest.raises(UnsupportedInputScript):
        sign_psbt_input(
            psbt=with_leaf(leaf_value=tap_leaf_value()[:-1] + b'\xc1'),
            index=0, privkey=tap_key(0))
    with pytest.raises(UnsupportedInputScript):
        sign_psbt_input(
            psbt=with_leaf(
                leaf_value=tap_tapscript() + b'\x00' + b'\xc0'),
            index=0, privkey=tap_key(0))
    # The tweaked NUMS output key must commit to the UTXO program.
    psbt = _signer_psbt()
    psbt.inputs[0].witness_utxo = psbt.inputs[0].witness_utxo._replace(
        script=bytes(make_p2tr_lock_script(output_key=b'\x33' * 32)))
    with pytest.raises(UtxoMismatch):
        sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(0))
    # A present TAP_MERKLE_ROOT must equal the computed leaf hash.
    psbt = _signer_psbt()
    psbt.inputs[0].tap_merkle_root = b'\x33' * 32
    with pytest.raises(UtxoMismatch):
        sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(0))
    psbt = _signer_psbt()
    psbt.inputs[0].tap_merkle_root = leaf
    assert sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(0)) is True
    # ОВ-17: absent or explicit SIGHASH_DEFAULT only.
    psbt = _signer_psbt()
    psbt.inputs[0].sighash_type = PSBT_SIGHASH_DEFAULT
    assert sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(0)) is True
    psbt = _signer_psbt()
    psbt.inputs[0].sighash_type = PSBT_SIGHASH_ALL
    with pytest.raises(UnsupportedSighashType):
        sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(0))
    # A present NON_WITNESS_UTXO must still hash to the outpoint.
    from yubtc.psbt import PsbtTransaction as PT, PsbtTxIn as PI, \
        PsbtTxOut as PO
    prev = PT(version=2, vin=(PI(txhash=b'\x99' * 32, n=0, script=b'',
                                 sequence=0xffffffff, witness=()),),
              vout=(PO(amount=PREV_AMOUNT, script=tap_spk()),), locktime=0)
    psbt = _signer_psbt()
    psbt.inputs[0].non_witness_utxo = prev
    with pytest.raises(UtxoMismatch):
        sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(0))


def test_signer_p2tr_scriptpath_incomplete_digest_context():
    """BIP-341 commits to all inputs: a second input without UTXO
    data leaves the digest incomputable -- the Signer skips (False),
    it does not guess."""
    psbt = create_psbt(
        unsigned_tx=PsbtTransaction(
            version=2,
            vin=(PsbtTxIn(txhash=b'\x44' * 32, n=0, script=b'',
                          sequence=0xfffffffe, witness=()),
                 PsbtTxIn(txhash=b'\x45' * 32, n=0, script=b'',
                          sequence=0xfffffffe, witness=())),
            vout=(PsbtTxOut(amount=SPEND_AMOUNT,
                            script=tap_dst_spk()),),
            locktime=0),
        inputs=tap_create_inputs() * 2)
    psbt.inputs[1].witness_utxo = None
    assert sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(0)) is False
    # No UTXO data at all: the dispatch arm never runs.
    lone = _signer_psbt()
    lone.inputs[0].witness_utxo = None
    assert sign_psbt_input(psbt=lone, index=0, privkey=tap_key(0)) is False


def _finalizer_psbt():
    """Creator + both fixture signers (the complete 2-of-3 input)."""
    psbt = tap_fixture_psbt()  # own key at nonce 0
    assert sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(1)) is True
    return psbt


def test_finalizer_p2tr_scriptpath_builds_reverse_slot_witness():
    """The Finalizer p2tr arm: FINAL_SCRIPTWITNESS is the R-MS-11
    stack (slots reversed, empty non-signer slot, script, control
    block), the intermediates are stripped, and UTXO/unknown fields
    survive."""
    psbt = _finalizer_psbt()
    # A foreign unknown pair survives finalization (BIP-174).
    psbt.inputs[0].unknown = [UnknownKv(key=b'\x16' + b'\x10' * 32,
                                        value=b'\x0a')]
    control = tap_control_block()
    script = tap_tapscript()
    from yubtc.psbt import finalize_psbt_input
    finalize_psbt_input(psbt=psbt, index=0)
    input_ = psbt.inputs[0]
    assert input_.final_scriptwitness is not None
    assert input_.tap_script_sigs == []
    assert input_.tap_leaf_scripts == []
    assert input_.tap_internal_key is None
    assert input_.tap_merkle_root is None
    assert input_.sighash_type is None
    assert input_.witness_utxo is not None
    assert input_.unknown == [UnknownKv(key=b'\x16' + b'\x10' * 32,
                                        value=b'\x0a')]
    # Decode the stack back and compare with the assembler output.
    sig0 = taproot_sign_sighash_untweaked(
        privkey=tap_key(0),
        sighash=taproot_scriptpath_sighash(
            tx=psbt.unsigned_tx, input_index=0,
            spend=[SpendInput(amount=PREV_AMOUNT,
                              script_pubkey=tap_spk())],
            leaf_hash=tapscript_leaf_hash(script=script)))
    sig1 = taproot_sign_sighash_untweaked(
        privkey=tap_key(1),
        sighash=taproot_scriptpath_sighash(
            tx=psbt.unsigned_tx, input_index=0,
            spend=[SpendInput(amount=PREV_AMOUNT,
                              script_pubkey=tap_spk())],
            leaf_hash=tapscript_leaf_hash(script=script)))
    # sig_slots are indexed in script-key order: the sorted script
    # keys are (nonce 2, nonce 0, nonce 1), so the key-0 signature is
    # the middle slot and key 2's slot stays empty.
    expected = make_multisig_tapscript_witness(
        script=script, control_block=control,
        sig_slots=[None, sig0, sig1])
    assert input_.final_scriptwitness == _encode_witness_stack(expected)
    # The raw bytes start with the element count (5).
    assert input_.final_scriptwitness[0] == 5
    assert len(input_.final_scriptwitness) == 271


def test_finalizer_p2tr_scriptpath_incomplete_and_corrupt_sigs():
    """Fewer than M 64-byte member signatures leave the input
    untouched (`IncompleteInput`); a wrong-length value blocks the
    input too."""
    from yubtc.psbt import finalize_psbt_input
    psbt = tap_fixture_psbt()  # own signature only (1 of 2)
    with pytest.raises(IncompleteInput):
        finalize_psbt_input(psbt=psbt, index=0)
    assert psbt.inputs[0].final_scriptwitness is None
    assert len(psbt.inputs[0].tap_script_sigs) == 1
    # A corrupted (63-byte) signature blocks finalization.
    psbt = _finalizer_psbt()
    psbt.inputs[0].tap_script_sigs[0] \
        = psbt.inputs[0].tap_script_sigs[0]._replace(sig=b'\x22' * 63)
    with pytest.raises(IncompleteInput):
        finalize_psbt_input(psbt=psbt, index=0)
    # A pinned non-default sighash blocks the input (ОВ-17).
    psbt = _finalizer_psbt()
    psbt.inputs[0].sighash_type = PSBT_SIGHASH_ALL
    with pytest.raises(IncompleteInput):
        finalize_psbt_input(psbt=psbt, index=0)


def test_finalizer_p2tr_scriptpath_rejections():
    """The Finalizer runs the Signer's structural/commitment ladder:
    foreign control blocks and scripts are `UnsupportedInputScript`,
    commitment mismatches are `UtxoMismatch`."""
    from yubtc.psbt import finalize_psbt_input
    psbt = _finalizer_psbt()
    psbt.inputs[0].tap_leaf_scripts[0] = TapLeafScript(
        control_block=b'\xc0' + b'\x33' * 32,
        script_with_version=tap_leaf_value())
    with pytest.raises(UnsupportedInputScript):
        finalize_psbt_input(psbt=psbt, index=0)
    psbt = _finalizer_psbt()
    psbt.inputs[0].tap_leaf_scripts[0] = TapLeafScript(
        control_block=tap_control_block(), script_with_version=b'')
    with pytest.raises(UnsupportedInputScript):
        finalize_psbt_input(psbt=psbt, index=0)
    psbt = _finalizer_psbt()
    psbt.inputs[0].tap_leaf_scripts[0] = TapLeafScript(
        control_block=tap_control_block(),
        script_with_version=tap_tapscript() + b'\x00' + b'\xc0')
    with pytest.raises(UnsupportedInputScript):
        finalize_psbt_input(psbt=psbt, index=0)
    psbt = _finalizer_psbt()
    psbt.inputs[0].witness_utxo = psbt.inputs[0].witness_utxo._replace(
        script=bytes(make_p2tr_lock_script(output_key=b'\x33' * 32)))
    with pytest.raises(UtxoMismatch):
        finalize_psbt_input(psbt=psbt, index=0)
    psbt = _finalizer_psbt()
    psbt.inputs[0].tap_merkle_root = b'\x33' * 32
    with pytest.raises(UtxoMismatch):
        finalize_psbt_input(psbt=psbt, index=0)


def test_finalizer_p2tr_scriptpath_over_signing_drops_the_tail():
    """All three members signed: the greedy rule takes the first M
    script keys and keeps the surplus member's slot empty -- an extra
    non-empty slot would push the CHECKSIGADD counter to N != M."""
    psbt = _finalizer_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=tap_key(2)) is True
    from yubtc.psbt import finalize_psbt_input
    finalize_psbt_input(psbt=psbt, index=0)
    tx = extract_transaction(psbt=psbt)
    stack = tx.vin[0].witness
    assert len(stack) == 5
    non_empty = [item for item in stack[:3] if item]
    assert len(non_empty) == 2
    # The surplus member is the *first* script key (nonce 2 sorts
    # lowest): its slot rides at the stack bottom -- empty.
    assert stack[0] == b''


def test_extractor_p2tr_scriptpath_layout_and_refusals():
    """The Extractor: the script-path spend needs FINAL_SCRIPTWITNESS
    (a FINAL_SCRIPTSIG on a `TAP_LEAF_SCRIPT` input is the P2WSH-symmetrical
    refusal); the wire tx carries an empty scriptSig and the stack."""
    psbt = _finalizer_psbt()
    finalize_psbt_input(psbt=psbt, index=0)
    tx = extract_transaction(psbt=psbt)
    assert tx.vin[0].script == b''
    assert len(tx.vin[0].witness) == 5
    assert tx.vin[0].witness[-2] == tap_tapscript()
    assert tx.vin[0].witness[-1] == tap_control_block()
    # A p2tr input with a FINAL_SCRIPTSIG *and* a tap leaf: refusal.
    hand = _signer_psbt()
    hand.inputs[0].final_scriptsig = b'\x00'
    with pytest.raises(IncompleteInput):
        extract_transaction(psbt=hand)
    # A key-path p2tr input (no tap leaf) keeps the Phase 13 rules:
    # no witness yet -> NotFinalized, the guard does not fire.
    from yubtc.crypto import taproot_output_key
    keypath = create_psbt(
        unsigned_tx=one_p2tr_keypath_tx(),
        inputs=[CreateInput(amount=PREV_AMOUNT,
                            script_pubkey=bytes(make_p2tr_lock_script(
                                output_key=taproot_output_key(
                                    internal_xonly=tap_pub(0)[1:33]))),
                            prev_tx=None)])
    keypath.inputs[0].final_scriptsig = b'\x00'
    with pytest.raises(NotFinalized):
        extract_transaction(psbt=keypath)


def one_p2tr_keypath_tx():
    """Unsigned tx spending a P2TR key-path fixture UTXO (the Phase 13
    shape, untouched by v0.3)."""
    return PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x55' * 32, n=0, script=b'',
                      sequence=0xfffffffe, witness=()),),
        vout=(PsbtTxOut(amount=SPEND_AMOUNT, script=tap_dst_spk()),),
        locktime=0)


# --- 8. The 2-of-3 e2e under the independent BIP-342 evaluator -----------


def test_two_of_three_e2e_evaluates_under_independent_bip342():
    """The finalized witness, evaluated by the from-scratch stack
    evaluator (BIP-342 CHECKSIGADD semantics + BIP-340 verification
    over the recomputed script-path digest), accepts exactly the real
    spend."""
    psbt = _finalizer_psbt()
    finalize_psbt_input(psbt=psbt, index=0)
    tx = extract_transaction(psbt=psbt)
    spend = [SpendInput(amount=PREV_AMOUNT, script_pubkey=tap_spk())]
    sighash = _ref_scriptpath_sighash(
        tx, 0, spend, tapscript_leaf_hash(script=tap_tapscript()))
    assert sighash == taproot_scriptpath_sighash(
        tx=tx, input_index=0, spend=spend,
        leaf_hash=tapscript_leaf_hash(script=tap_tapscript()))
    assert eval_tapscript_idiom(list(tx.vin[0].witness), sighash) is True


def test_evaluator_rejects_consensus_mutations():
    """The mutation table: wrong slot, over-signing, a filled
    non-signer slot, an empty signer slot, a mutated control block or
    script -- every mutation is a consensus failure under the
    independent evaluator."""
    psbt = _finalizer_psbt()
    finalize_psbt_input(psbt=psbt, index=0)
    tx = extract_transaction(psbt=psbt)
    spend = [SpendInput(amount=PREV_AMOUNT, script_pubkey=tap_spk())]
    sighash = _ref_scriptpath_sighash(
        tx, 0, spend, tapscript_leaf_hash(script=tap_tapscript()))
    good = list(tx.vin[0].witness)
    control = tap_control_block()
    script = tap_tapscript()
    sig0 = good[1]  # w_1 (script key 0, top)
    sig1 = good[0]  # w_2
    garbage = b'\x77' * 64

    def ev(stack):
        return eval_tapscript_idiom(stack, sighash)

    # Wrong slot: the two signatures swapped.
    assert ev([sig0, sig1, b'', script, control]) is False
    # Over-signing: all three slots filled (counter N != M).
    sig2 = taproot_sign_sighash_untweaked(
        privkey=tap_key(2), sighash=sighash)
    assert ev([sig2, sig1, sig0, script, control]) is False
    # A non-signer slot filled with a failing signature.
    assert ev([garbage, sig1, sig0, script, control]) is False
    # An empty signer slot (counter < M).
    assert ev([b'', b'', sig0, script, control]) is False
    # Mutated control block: the reveal no longer commits to the leaf
    # (parity bit flipped).
    bad_control = bytes([control[0] ^ 0x01]) + control[1:]
    assert ev([b'', sig1, sig0, script, bad_control]) is False
    # Mutated script: no longer the canonical idiom.
    assert ev([b'', sig1, sig0, script[:-1] + b'\x9c', control]) is False
    # Truncated stack: not a script-path spend at all.
    assert ev([script, control]) is False
    # A valid stack under a *different* digest fails (every signature
    # commits to the exact sighash).
    other_sighash = _ref_scriptpath_sighash(
        tx, 0, [SpendInput(amount=PREV_AMOUNT + 1,
                           script_pubkey=tap_spk())],
        tapscript_leaf_hash(script=script))
    assert eval_tapscript_idiom(good, other_sighash) is False


# --- 9. The Rust-oracle parity fixture -----------------------------------


def _row_chain(seed: str, key_nonces: list, own_nonce: int):
    """Rebuild one fixture row's full pipeline from the seed (mirrors
    the documented recipe: Creator + own Signer -> cosigner Signer ->
    Combiner -> Finalizer -> Extractor)."""
    keys = [tap_pub(k, seed) for k in key_nonces]
    addr, redeem = ms_create_address(n=3, m=2, keys=keys, form=MsForm.P2TR)
    leaf_hash = tapscript_leaf_hash(script=redeem)
    control = tapscript_control_block(internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
                                      leaf_hash=leaf_hash)
    output_key = tapscript_output_key(internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
                                      leaf_hash=leaf_hash)
    spk = bytes(make_p2tr_lock_script(output_key=output_key))
    dst_pub = tap_pub(DST_NONCE, seed)
    dst_spk = bytes(make_p2wpkh_lock_script(hash160=hash160(dst_pub)))
    unsigned_tx = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x44' * 32, n=0, script=b'',
                      sequence=0xfffffffe, witness=()),),
        vout=(PsbtTxOut(amount=SPEND_AMOUNT, script=dst_spk),),
        locktime=0)
    inputs = [CreateInput(amount=PREV_AMOUNT, script_pubkey=spk,
                          prev_tx=None,
                          tap_leaf_script=redeem
                          + bytes([TAPSCRIPT_LEAF_VERSION]))]
    psbt_a = create_psbt(unsigned_tx=unsigned_tx, inputs=inputs)
    unsigned = to_base64(psbt=psbt_a)
    cosigner_nonce = next(k for k in key_nonces if k != own_nonce)
    spend = [SpendInput(amount=PREV_AMOUNT, script_pubkey=spk)]
    sighash = taproot_scriptpath_sighash(tx=unsigned_tx, input_index=0,
                                         spend=spend,
                                         leaf_hash=leaf_hash)
    assert sign_psbt_input(psbt=psbt_a, index=0,
                           privkey=tap_key(own_nonce, seed)) is True
    signed_a = to_base64(psbt=psbt_a)
    own_sig = next(s.sig for s in psbt_a.inputs[0].tap_script_sigs
                   if s.x_only == tap_pub(own_nonce, seed)[1:33])
    psbt_b = create_psbt(unsigned_tx=unsigned_tx, inputs=inputs)
    assert sign_psbt_input(psbt=psbt_b, index=0,
                           privkey=tap_key(cosigner_nonce, seed)) is True
    combined = combine_psbt(psbt=psbt_a, other=psbt_b)
    signed_ab = to_base64(psbt=combined)
    finalize_psbt(psbt=combined)
    finalized = to_base64(psbt=combined)
    tx = extract_transaction(psbt=combined)
    return {
        'address': addr, 'redeem_hex': redeem.hex(),
        'leaf_hash_hex': leaf_hash.hex(), 'control_hex': control.hex(),
        'output_key_hex': output_key.hex(),
        'internal_hex': bytes(MS_TAPSCRIPT_INTERNAL_KEY).hex(),
        'script_pubkey_hex': spk.hex(),
        'sighash_hex': sighash.hex(), 'own_sig_hex': own_sig.hex(),
        'unsigned': unsigned, 'signed_a': signed_a,
        'signed_ab': signed_ab, 'combined': signed_ab,
        'finalized': finalized, 'wire_hex': tx.serialize_wire().hex(),
        'txid': tx.id().hex(),
        'witness_items': len(tx.vin[0].witness),
        'witness_stack_hex': [item.hex() for item in tx.vin[0].witness],
        'final_scriptwitness_len':
            len(combined.inputs[0].final_scriptwitness),
    }


def test_fixture_rows_match_the_rust_oracle_chain():
    """Every fixture row -- the Rust oracle's bytes at commit e84dfaa
    (the recipe inside the fixture regenerates it) -- must be
    reproduced byte-for-byte by the mirror: quorum constants, the
    five PSBT stages, the digest, the signatures and the final
    witness."""
    rows = _load_fixture()['rows']
    assert len(rows) == 16
    for row in rows:
        got = _row_chain(seed=row['seed'],
                         key_nonces=row['key_nonces'],
                         own_nonce=row['own_nonce'])
        for field, value in got.items():
            assert value == row[field], \
                f"row {row['seed']}/{row['own_nonce']}: {field} diverges"


def test_fixture_script_table_and_pins():
    """The fixture's script table (synthetic key sets, 1..15 keys) and
    the static pins are reproduced by the mirror builders."""
    doc = _load_fixture()
    for entry in doc['script_table']:
        keys = [bytes.fromhex(h) for h in entry['keys_hex']]
        script = make_multisig_tapscript(m=entry['m'], keys=keys)
        assert script == bytes.fromhex(entry['script_hex'])
        assert len(script) == entry['script_len']
        leaf = tapscript_leaf_hash(script=script)
        assert leaf == bytes.fromhex(entry['leaf_hash_hex'])
        control = tapscript_control_block(
            internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY, leaf_hash=leaf)
        assert control == bytes.fromhex(entry['control_hex'])
        assert len(control) == doc['pins']['control_block_len']
        assert redeem2taproot_addr(script=script) == entry['address']
        assert tapscript_output_key(
            internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
            leaf_hash=leaf) == bytes.fromhex(entry['output_key_hex'])
    pin = doc['sort_divergence_pin']
    pair = [bytes.fromhex(pin['k_compressed_hex'])[1:],
            bytes.fromhex(pin['l_compressed_hex'])[1:]]
    assert make_multisig_tapscript(m=2, keys=pair) \
        == bytes.fromhex(pin['script_hex'])


# --- 10. The wallet surface: forms, key encodings, Creator ---------------


class _MockBackend:
    """In-memory backend for the p2tr Creator tests: one canned UTXO,
    no raw transactions (any raw_transaction call would fail the test
    -- the witness form fetches nothing)."""

    def __init__(self, utxo):
        self.utxo = utxo

    def get_unspent(self, address, **kwargs):
        return [self.utxo]

    def get_info(self, address, **kwargs):
        return {'total_received': 0}

    def send_tx(self, rawtx, **kwargs):
        raise AssertionError('the p2tr Creator never broadcasts')

    def raw_transaction(self, txid, **kwargs):
        raise AssertionError('the p2tr Creator never fetches prev txs')


def _wallet_prev_backend(script: bytes):
    """A 60_000-sat UTXO at `script` (outpoint 0x77*32:0), confirmations 6."""
    prev = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x77' * 32, n=0, script=b'',
                      sequence=0xffffffff, witness=()),),
        vout=(PsbtTxOut(amount=60_000, script=script),), locktime=0)
    backend = _MockBackend(utxo={
        'tx_hash': prev.id().hex(), 'tx_output_n': 0, 'value': 60_000,
        'script': script.hex(), 'confirmations': 6})
    return backend


def test_parse_ms_keys_enforces_the_form_encoding():
    """R-MS-10: p2sh/p2wsh take 66-hex compressed keys, p2tr 64-hex
    x-only -- mixing, wrong lengths, bad hex and non-strings are
    `InvalidKeyEncoding`."""
    compressed = tap_pub(0)
    xonly = compressed[1:33]
    # p2tr: x-only hex in, 0x02-prefixed 33-byte keys out.
    assert parse_ms_keys(keys=[xonly.hex()], form='p2tr') \
        == [b'\x02' + xonly]
    assert parse_ms_keys(keys=[compressed.hex()], form='p2wsh') \
        == [compressed]
    for form in ('p2tr', 'p2sh', 'p2wsh'):
        for bad in ('', 'zz', xonly.hex() + 'aa', b'\x02' + xonly,
                    '04' + xonly.hex() + 'ab'):
            with pytest.raises(InvalidKeyEncoding):
                parse_ms_keys(keys=[bad], form=form)
    # The compressed key is rejected on the p2tr side (and vice
    # versa).
    with pytest.raises(InvalidKeyEncoding):
        parse_ms_keys(keys=[compressed.hex()], form='p2tr')
    with pytest.raises(InvalidKeyEncoding):
        parse_ms_keys(keys=[xonly.hex()], form='p2sh')
    from yubtc.wallet import MsError
    assert issubclass(InvalidKeyEncoding, MsError)
    assert 'x-only' in str(InvalidKeyEncoding())


def test_ms_create_address_p2tr_form_and_three_form_quorum():
    """One quorum, three addresses: the p2tr form derives the
    CHECKSIGADD tapscript (different bytes than the p2sh/p2wsh
    redeem) and the `bc1p...` bech32m address; p2sh/p2wsh keep their
    forms."""
    keys = tap_keys()
    addr_p2tr, tapscript = ms_create_address(n=3, m=2, keys=keys,
                                             form=MsForm.P2TR)
    addr_p2sh, redeem = ms_create_address(n=3, m=2, keys=keys,
                                          form=MsForm.P2SH)
    addr_p2wsh, redeem_wsh = ms_create_address(n=3, m=2, keys=keys,
                                               form=MsForm.P2WSH)
    assert redeem == redeem_wsh
    assert tapscript != redeem
    assert addr_p2tr.startswith('bc1p')
    assert len(addr_p2tr) == 62
    assert extract_multisig_tapscript(script=tapscript)[0] == 2
    assert redeem2taproot_addr(script=tapscript) == addr_p2tr
    # Permutation invariance (R-MS-4 with the R-MS-10 x-only sort).
    for perm in ([2, 1, 0], [1, 2, 0]):
        assert ms_create_address(n=3, m=2,
                                 keys=[keys[i] for i in perm],
                                 form=MsForm.P2TR) == (addr_p2tr, tapscript)
    assert make_multisig_redeem_script(m=2, keys=sorted(keys)) == redeem


def test_ms_create_address_p2tr_bounds_fallback():
    """Sub-33-byte keys cannot reach the tapscript builder through the
    validated path; the typed refusal is `QuorumBounds` (the same
    mapping the p2sh/p2wsh arms use for a degenerate script)."""
    short = [tap_pub(0)[1:], tap_pub(1)[1:]]
    with pytest.raises(QuorumBounds):
        ms_create_address(n=2, m=1, keys=short, form=MsForm.P2TR)


def test_ms_quorum_lock_script_three_forms():
    """The shared Creator-side lock-script derivation: hash160 /
    SHA-256 / tweaked-NUMS commitments respectively."""
    redeem = tap_tapscript()
    assert bytes(ms_quorum_lock_script(redeem=redeem,
                                       form=MsForm.P2SH)) \
        == bytes(make_p2sh_lock_script(hash160=hash160(redeem)))
    assert bytes(ms_quorum_lock_script(redeem=redeem,
                                       form=MsForm.P2WSH)) \
        == bytes(make_p2wsh_lock_script(sha256=sha256(redeem)))
    assert ms_quorum_lock_script(redeem=redeem, form=MsForm.P2TR) \
        == tap_spk()


def test_ms_select_utxos_smallest_prefix():
    """The greedy selection the p2tr Creator reuses: walk in the
    network order, stop at the first prefix reaching the target."""
    utxos = [{'value': 100}, {'value': 200}, {'value': 400}]
    assert ms_select_utxos(utxos=utxos, target=250) == utxos[:2]
    assert ms_select_utxos(utxos=utxos, target=None) == utxos


def wallet_tap_quorum():
    """The wallet-seed 2-of-3 tapscript quorum: own key at nonce 0
    (WALLET_SEED), cosigners at nonces 1-2; the quorum address, the
    tapscript and its lock script."""
    keys = [tap_pub(1, WALLET_SEED), tap_pub(2, WALLET_SEED)]
    addr, redeem = ms_create_address(
        n=3, m=2, keys=[tap_pub(0, WALLET_SEED)] + keys,
        form=MsForm.P2TR)
    script = ms_quorum_lock_script(redeem=redeem, form=MsForm.P2TR)
    return keys, addr, redeem, script


def test_ms_create_psbt_p2tr_builds_and_signs_over_a_mock_backend():
    """The p2tr Creator over the mock backend: no prev-tx fetch, the
    witness-form UTXO field, the typed 0x15/0x17 fields, the own
    `TAP_SCRIPT_SIG`, the fee loop over the R-MS-11 sized witness --
    and the full chain to the extracted witness spend."""
    _keys, _addr, redeem, script = wallet_tap_quorum()
    # The raw map is deliberately empty: any raw_transaction call
    # would fail the test through the mock's error arm (BIP-341
    # commits the amount via WITNESS_UTXO).
    backend = _wallet_prev_backend(script)
    dst = pubkey2segwit_addr(pubkey=tap_pub(8, WALLET_SEED))
    from yubtc.wallet import ms_create_psbt
    outcome = ms_create_psbt(seed=WALLET_SEED, passphrase='',
                             backend=backend, dst=dst, amount=50_000,
                             n=3, m=2,
                             keys=[tap_pub(1, WALLET_SEED),
                                   tap_pub(2, WALLET_SEED)],
                             own_nonce=0, confirmations=6, feekb=1000,
                             fee=0, form=MsForm.P2TR)
    from yubtc.psbt import from_base64
    psbt = from_base64(s=outcome.psbt_b64)
    assert len(psbt.inputs) == 1
    assert psbt.inputs[0].non_witness_utxo is None
    assert psbt.inputs[0].witness_utxo.script == script
    assert psbt.inputs[0].witness_script is None
    assert psbt.inputs[0].tap_leaf_scripts[0].script_with_version \
        == redeem + bytes([TAPSCRIPT_LEAF_VERSION])
    assert psbt.inputs[0].tap_leaf_scripts[0].control_block \
        == tapscript_control_block(
            internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
            leaf_hash=tapscript_leaf_hash(script=redeem))
    assert psbt.inputs[0].tap_internal_key \
        == bytes(MS_TAPSCRIPT_INTERNAL_KEY)
    assert len(psbt.inputs[0].tap_script_sigs) == 1
    # Fee arithmetic and the cashback to the quorum address.
    assert outcome.fee + outcome.amount + outcome.cashback == 60_000
    assert outcome.fee > 0
    assert psbt.unsigned_tx.vout[0].script == script
    # Completion: the second cosigner signs, finalize + extract yield
    # the R-MS-11 witness (N + 2 items, two non-empty slots).
    assert sign_psbt_input(psbt=psbt, index=0,
                           privkey=tap_key(1, WALLET_SEED)) is True
    finalize_psbt(psbt=psbt)
    tx = extract_transaction(psbt=psbt)
    assert tx.vin[0].script == b''
    assert len(tx.vin[0].witness) == 5
    assert sum(1 for item in tx.vin[0].witness[:3] if item) == 2
    assert tx.vin[0].witness[3] == redeem
    assert len(tx.vin[0].witness[4]) == 33


def test_ms_create_psbt_p2tr_requires_participation():
    """`own_nonce=None` is `NotAParticipant` on the p2tr form too --
    yubtc spends only quorums it participates in."""
    from yubtc.wallet import ms_create_psbt
    _keys, _addr, redeem, script = wallet_tap_quorum()
    backend = _wallet_prev_backend(script)
    dst = pubkey2segwit_addr(pubkey=tap_pub(8, WALLET_SEED))
    with pytest.raises(NotAParticipant):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, n=3, m=2,
                       keys=[tap_pub(1, WALLET_SEED),
                             tap_pub(2, WALLET_SEED)],
                       own_nonce=None, confirmations=6, feekb=1000,
                       fee=0, form=MsForm.P2TR)


def test_dust_threshold_p2tr_pin():
    """The p2tr dust threshold stays the existing `DUST_THRESHOLD_P2TR
    = 330` -- no new dust constant appears in v0.3 (the taproot output
    is 43 bytes spending 67 vB)."""
    from yubtc.fwd import DUST_THRESHOLD_P2TR
    assert DUST_THRESHOLD_P2TR == 330
    assert is_dust(amount=329, script=bytes(make_p2tr_lock_script(
        output_key=tapscript_output_key(
            internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
            leaf_hash=tapscript_leaf_hash(script=tap_tapscript())))))
    assert not is_dust(amount=330, script=bytes(make_p2tr_lock_script(
        output_key=tapscript_output_key(
            internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
            leaf_hash=tapscript_leaf_hash(script=tap_tapscript())))))


# --- 11. The strict P2TR address decoder ---------------------------------


def test_decode_taproot_addr_round_trip_and_refusals():
    """The P2TR-only decoder: bech32m v1 with a 32-byte program; v0
    programs, 20-byte programs, foreign HRPs, malformed payloads and
    plain-bech32 checksums are typed refusals."""
    from yubtc.bech32 import BECH32, BECH32M, bytes_to_5bit, encode
    from yubtc.crypto import (SegWitInvalidChecksum, SegWitInvalidHrp,
                              SegWitInvalidStructure,
                              SegWitUnsupportedProgram,
                              decode_taproot_addr)
    script = tap_tapscript()
    addr = redeem2taproot_addr(script=script)
    wp = decode_taproot_addr(address=addr)
    assert wp.version == 1
    assert wp.program == tapscript_output_key(
        internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
        leaf_hash=tapscript_leaf_hash(script=script))
    # A v0 witness program (the bc1q shape) is not a P2TR address.
    with pytest.raises(SegWitUnsupportedProgram):
        decode_taproot_addr(address=pubkey2segwit_addr(pubkey=tap_pub(3)))
    # A 20-byte v1 program: structurally bech32m, wrong length.
    short = encode(hrp='bc', encoding=BECH32M,
                   data=bytes([1]) + bytes_to_5bit(data=b'\x22' * 20))
    with pytest.raises(SegWitUnsupportedProgram):
        decode_taproot_addr(address=short)
    # A v1 32-byte program with a plain bech32 checksum.
    plain = encode(hrp='bc', encoding=BECH32,
                   data=bytes([1]) + bytes_to_5bit(data=b'\x22' * 32))
    with pytest.raises(SegWitInvalidChecksum):
        decode_taproot_addr(address=plain)
    # Foreign HRP.
    tb = encode(hrp='tb', encoding=BECH32M,
                data=bytes([1]) + bytes_to_5bit(data=b'\x22' * 32))
    with pytest.raises(SegWitInvalidHrp):
        decode_taproot_addr(address=tb)
    # An empty payload and an unregroupable 5-bit payload.
    with pytest.raises(SegWitInvalidStructure):
        decode_taproot_addr(address=encode(hrp='bc', encoding=BECH32M,
                                           data=b''))
    with pytest.raises(SegWitInvalidStructure):
        decode_taproot_addr(address=encode(hrp='bc', encoding=BECH32M,
                                           data=bytes([0, 1])))
    # A corrupted checksum maps the bech32 codec error to its typed
    # SegWit counterpart.
    broken = addr[:-3] + ('q' if addr[-3] != 'q' else 'p') + addr[-2:]
    from yubtc.crypto import SegWitAddrError
    with pytest.raises(SegWitAddrError):
        decode_taproot_addr(address=broken)
