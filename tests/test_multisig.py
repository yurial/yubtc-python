"""Tests for the Phase 15 multi-sig (P2SH) mirror of `yubtc core`.

Six layers, mirroring the multisig tests of the Rust oracle
(`core/src/script.rs`, `core/src/psbt.rs`, `core/src/wallet.rs`):

1. **Script vectors** (`yubtc.script`): the canonical bare
   CHECKMULTISIG redeem builder/extractor (R-MS-2/3/4: bounds
   0/1/15/16, duplicates, BIP-67 sort, strict shape checks), the
   R-MS-5 `scriptSig` layout (`OP_0 ‖ sigs ‖ redeem`), the
   `push_data` OP_PUSHDATA1/2 escalations and the P2SH quorum
   address.
2. **CompactSize pins (DEVIATIONS.md D-002)**: transaction lengths
   are Bitcoin CompactSize -- the multisig `scriptSig` (>= 253 bytes)
   is the first yubtc script past the LEB128/CompactSize divergence
   point (253 encodes `fd fd 00`, never the LEB128 `fd 01`).
3. **PSBT branches**: the P2SH-multisig arms of Creator / Signer /
   Finalizer / Extractor (`REDEEM_SCRIPT` 0x04 W/R, membership
   signing with `scriptCode = redeem`, the finalize layout, the
   extractor rules), per the spec's validation table.
4. **2-of-3 e2e** verified by an **independent CHECKMULTISIG
   evaluator** implemented in this module (local wire parser, local
   sighash re-encoding, local stack semantics, coincurve prehash
   verification -- shares no code with `yubtc`), with BIP-147 /
   swap / foreign-signer / truncation mutations failing it.
5. **Wallet quorum surface**: `ms_create_address` typed errors +
   R-MS-4 permutation invariance, the R-MS-6 own-key derivation,
   `ms_wif_own_key`, `ms_select_utxos` and the `ms_create_psbt`
   Creator orchestration over a mock backend (ОВ-12/ОВ-13).
6. **Parity KAT** (`MS_ROWS`): byte-exact stages generated from the
   Rust oracle -- see the `MS_ROWS` comment for the production recipe.
"""
import base64
import hashlib
import itertools
from struct import pack

import pytest

from yubtc.crypto import (privkey2privwif, privkey2pubkey, pubkey2segwit_addr,
                          seed2privkey)
from yubtc.fwd import MS_MAX_PUBKEYS, PSBT_SIGHASH_ALL
from yubtc.hash import hash160
from yubtc.misc import is_dust
from yubtc.psbt import (CreateInput, IncompleteInput, NotFinalized,
                        PsbtTransaction, PsbtTxIn, PsbtTxOut,
                        UnsupportedInputScript, UnsupportedSighashType,
                        UtxoMismatch, combine_psbt, create_psbt,
                        extract_transaction, finalize_psbt,
                        finalize_psbt_input, parse_psbt, serialize_psbt,
                        sign_psbt, sign_psbt_input, to_base64)
from yubtc.script import (InvalidMultisigRedeem, OP_0, OP_CHECKMULTISIG,
                          OP_PUSHDATA1, OP_PUSHDATA2, extract_multisig_quorum,
                          make_multisig_redeem_script,
                          make_multisig_script_sig, make_p2sh_lock_script,
                          push_data, push_data_len, redeem2p2sh_addr)
from yubtc.transaction import CIn, compact_size, toVarInt
from yubtc.wallet import (DuplicateKey, ForeignWif, KeyCountMismatch,
                          MsError, NotAParticipant, QuorumBounds,
                          ms_create_address, ms_create_psbt, ms_own_privkey,
                          ms_own_pubkey, ms_select_utxos, ms_wif_own_key)


# --- Fixtures (mirror the Rust oracle's multisig fixtures) --------------
#
# SEED is the psbt-layer fixture ("phase15multisig" — the Rust MS_SEED);
# WALLET_SEED the wallet-layer one ("phase15wallet" — MS_WALLET_SEED).
# The cascade KDF (empty passphrase) keeps derivation offline and
# deterministic; the own key at nonce n is the legacy form (R-MS-6).

SEED = 'phase15multisig'
WALLET_SEED = 'phase15wallet'


def ms_key(nonce: int, seed: str = SEED):
    return seed2privkey(seed=seed, nonce=nonce, passphrase='', kdf='yubtc')


def ms_pub(nonce: int, seed: str = SEED) -> bytes:
    return privkey2pubkey(ms_key(nonce, seed))


def ms_redeem() -> bytes:
    return make_multisig_redeem_script(m=2, keys=[ms_pub(0), ms_pub(1),
                                                  ms_pub(2)])


def ms_redeem_keys() -> list:
    return extract_multisig_quorum(script=ms_redeem())[1]


def ms_p2sh_spk() -> bytes:
    return bytes(make_p2sh_lock_script(hash160=hash160(ms_redeem())))


def ms_dst_spk() -> bytes:
    # Foreign native-P2WPKH destination (fixture nonce 9), as the Rust
    # fixture_spk(9, AddrType::Native).
    from yubtc.script import make_p2wpkh_lock_script
    return bytes(make_p2wpkh_lock_script(hash160=hash160(ms_pub(9))))


def ms_prev_tx() -> PsbtTransaction:
    """Prev tx paying 60_000 sat to the fixture P2SH address."""
    return PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x22' * 32, n=0, script=b'',
                      sequence=0xffffffff, witness=()),),
        vout=(PsbtTxOut(amount=60000, script=ms_p2sh_spk()),), locktime=0)


def ms_unsigned_tx() -> PsbtTransaction:
    """Unsigned tx spending the fixture output to the foreign dst."""
    return PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=ms_prev_tx().id(), n=0, script=b'',
                      sequence=0xfffffffe, witness=()),),
        vout=(PsbtTxOut(amount=50000, script=ms_dst_spk()),), locktime=0)


def ms_fixture_psbt():
    """Creator output for the happy-path fixture (the same shape the
    Rust `ms_create_psbt` test fixture builds)."""
    return create_psbt(unsigned_tx=ms_unsigned_tx(),
                       inputs=[CreateInput(amount=60000,
                                           script_pubkey=ms_p2sh_spk(),
                                           prev_tx=ms_prev_tx(),
                                           redeem_script=ms_redeem())])


# --- 1. Script vectors --------------------------------------------------


def test_multisig_opcodes_have_expected_byte_values():
    # Pins the opcodes the multisig surface references. Any shift is
    # balance-breaking with no compile-time signal.
    assert OP_0 == 0x00
    assert OP_CHECKMULTISIG == 0xae
    assert OP_PUSHDATA1 == 0x4c
    assert OP_PUSHDATA2 == 0x4d
    assert MS_MAX_PUBKEYS == 15


def test_push_data_single_opcode_form_and_boundaries():
    assert push_data(data=b'') == b'\x00'
    item = b'\xaa' * 33
    assert push_data(data=item) == bytes([33]) + item
    edge = b'\xaa' * 0x4b
    assert push_data(data=edge) == bytes([0x4b]) + edge
    assert push_data_len(length=0x4b) == 1
    assert push_data_len(length=75) == 1
    assert push_data_len(length=0) == 1


def test_push_data_escalates_to_op_pushdata1_above_75_bytes():
    item = b'\xaa' * 76
    assert push_data(data=item) == bytes([OP_PUSHDATA1, 76]) + item
    item = b'\xaa' * 255
    assert push_data(data=item) == bytes([OP_PUSHDATA1, 255]) + item
    assert push_data_len(length=76) == 2
    assert push_data_len(length=255) == 2


def test_push_data_escalates_to_op_pushdata2_above_255_bytes():
    item = b'\xaa' * 256
    assert push_data(data=item) == bytes([OP_PUSHDATA2, 0x00, 0x01]) + item
    item = b'\xaa' * 514
    assert push_data(data=item) == bytes([OP_PUSHDATA2]) \
        + (514).to_bytes(2, 'little') + item
    assert push_data_len(length=256) == 3
    assert push_data_len(length=514) == 3


def test_push_data_rejects_items_beyond_op_pushdata2_reach():
    with pytest.raises(ValueError, match='item too long'):
        push_data(data=b'\xaa' * 0x10000)


def test_push_data_round_trips_through_a_length_prefix_read():
    # Decode every encoding arm back with a local length-prefix read.
    for size in (0, 1, 33, 75, 76, 255, 256, 514):
        item = bytes(size)
        encoded = push_data(data=item)
        head = encoded[0]
        if head <= 0x4b:
            length, payload = head, encoded[1:]
        elif head == OP_PUSHDATA1:
            length, payload = encoded[1], encoded[2:]
        else:
            assert head == OP_PUSHDATA2
            length, payload = (int.from_bytes(encoded[1:3], 'little'),
                               encoded[3:])
        assert length == size
        assert payload == item
        assert len(encoded) == len(item) + push_data_len(length=size)


def test_multisig_redeem_has_canonical_layout_2_of_3():
    # Three syntactically-distinct canonical keys in deliberately
    # unsorted order (the Rust ms_keys fixture).
    k1 = bytes([0x02]) + bytes(31) + bytes([0x01])
    k2 = bytes([0x02]) + bytes(31) + bytes([0x02])
    k3 = bytes([0x03]) + bytes(31) + bytes([0x01])
    redeem = make_multisig_redeem_script(m=2, keys=[k3, k1, k2])
    # OP_m + 3·(1 + 33) + OP_n + OP_CHECKMULTISIG = 105 bytes.
    assert len(redeem) == 105
    assert redeem[0] == 0x52
    assert redeem[1] == 0x21
    assert redeem[2:35] == k1  # 0x02…01 is the smallest
    assert redeem[35] == 0x21
    assert redeem[36:69] == k2
    assert redeem[69] == 0x21
    assert redeem[70:103] == k3
    assert redeem[103] == 0x53
    assert redeem[104] == OP_CHECKMULTISIG


def test_multisig_redeem_sorts_keys_bip67():
    keys = [ms_pub(i) for i in range(3)]
    orders = [keys[::-1], [keys[1], keys[0], keys[2]],
              [keys[2], keys[1], keys[0]]]
    scripts = [make_multisig_redeem_script(m=2, keys=o) for o in orders]
    # The same set in any argument order yields byte-identical
    # scripts (R-MS-4).
    assert scripts[0] == scripts[1] == scripts[2] == ms_redeem()
    # And the script order is the lexicographic byte sort.
    for pos, key in zip(range(2, 2 + 34 * 3, 34), sorted(keys)):
        assert ms_redeem()[pos:pos + 33] == key


def test_multisig_redeem_bounds_rejections():
    keys = [ms_pub(0), ms_pub(1), ms_pub(2)]
    for m, ks in [(0, keys), (4, keys), (1, [])]:
        with pytest.raises(InvalidMultisigRedeem):
            make_multisig_redeem_script(m=m, keys=ks)
    # n = 16 (above MS_MAX_PUBKEYS) with 16 distinct keys, so the
    # duplicate check is not what fires.
    distinct = [bytes([0x02]) + bytes(31) + bytes([i]) for i in range(16)]
    with pytest.raises(InvalidMultisigRedeem):
        make_multisig_redeem_script(m=16, keys=distinct)


def test_multisig_redeem_rejects_duplicate_keys():
    k1 = bytes([0x02]) + bytes(31) + bytes([0x01])
    k2 = bytes([0x02]) + bytes(31) + bytes([0x02])
    with pytest.raises(InvalidMultisigRedeem):
        make_multisig_redeem_script(m=2, keys=[k1, k1, k2])
    # Even one duplicated pair inside an otherwise valid 2-of-2.
    with pytest.raises(InvalidMultisigRedeem):
        make_multisig_redeem_script(m=2, keys=[k1, k1])


def test_multisig_redeem_boundaries_1_of_1_and_15_of_15():
    single = bytes([0x02]) + bytes(31) + bytes([0x07])
    one = make_multisig_redeem_script(m=1, keys=[single])
    assert len(one) == 37
    assert one[0] == 0x51
    assert one[35] == 0x51
    assert one[36] == OP_CHECKMULTISIG
    assert extract_multisig_quorum(script=one) == (1, [single])

    # 15-of-15: 34·15 + 3 = 513 bytes — inside the 520-byte push limit
    # (the R-MS-2 rationale).
    distinct = [bytes([0x02]) + bytes(31) + bytes([i + 1])
                for i in range(15)]
    big = make_multisig_redeem_script(m=15, keys=distinct)
    assert len(big) == 513
    assert big[0] == 0x5f
    assert big[511] == 0x5f
    assert big[512] == OP_CHECKMULTISIG
    m, keys = extract_multisig_quorum(script=big)
    assert (m, keys) == (15, distinct)


def test_multisig_extract_round_trip_and_script_order():
    # Script order is sorted: ms_pub(0) < ms_pub(1) < ms_pub(2) is not
    # guaranteed a priori — assert via the BIP-67 sort of the builder.
    redeem = make_multisig_redeem_script(m=1, keys=[ms_pub(2), ms_pub(0),
                                                    ms_pub(1)])
    m, keys = extract_multisig_quorum(script=redeem)
    assert (m, keys) == (1, sorted([ms_pub(0), ms_pub(1), ms_pub(2)]))
    # Builder -> extractor round trip at the boundary sizes.
    for n in (1, 2, 15):
        ks = sorted([bytes([0x02]) + bytes(31) + bytes([i + 1])
                     for i in range(n)])
        r = make_multisig_redeem_script(m=n, keys=ks)
        assert extract_multisig_quorum(script=r) == (n, ks)


def test_multisig_extract_rejects_bad_lengths_and_opcodes():
    keys = [ms_pub(0), ms_pub(1), ms_pub(2)]
    canonical = make_multisig_redeem_script(m=2, keys=keys)
    assert len(canonical) == 105

    # Truncations and extensions.
    for bad in (b'', canonical[:36], canonical[:104], canonical + b'\x00'):
        with pytest.raises(InvalidMultisigRedeem):
            extract_multisig_quorum(script=bad)

    # Wrong OP_m at the head (OP_0 is not a small-integer push;
    # m = 4 > n = 3).
    for head in (0x00, 0x54):
        bad_m = bytearray(canonical)
        bad_m[0] = head
        with pytest.raises(InvalidMultisigRedeem):
            extract_multisig_quorum(script=bytes(bad_m))

    # Wrong OP_n in the tail (OP_16 — above MS_MAX_PUBKEYS).
    bad_n = bytearray(canonical)
    bad_n[103] = 0x60
    with pytest.raises(InvalidMultisigRedeem):
        extract_multisig_quorum(script=bytes(bad_n))

    # Wrong terminal opcode.
    bad_term = bytearray(canonical)
    bad_term[104] = 0xac  # OP_CHECKSIG
    with pytest.raises(InvalidMultisigRedeem):
        extract_multisig_quorum(script=bytes(bad_term))

    # Wrong push prefix (0x20 instead of 0x21)…
    bad_push = bytearray(canonical)
    bad_push[1] = 0x20
    with pytest.raises(InvalidMultisigRedeem):
        extract_multisig_quorum(script=bytes(bad_push))

    # …and OP_PUSHDATA1 wrappers instead of the single-opcode pushes:
    # same pushed payload, different envelope — non-canonical form.
    wrapped = bytearray([0x52])
    for key in sorted(keys):
        wrapped += bytes([OP_PUSHDATA1, 0x21]) + key
    wrapped += bytes([0x53, OP_CHECKMULTISIG])
    with pytest.raises(InvalidMultisigRedeem):
        extract_multisig_quorum(script=bytes(wrapped))

    # Non-canonical pubkey prefix inside a 0x21 push (0x04 =
    # uncompressed-style prefix; 0x05 likewise).
    for pos, prefix in ((2, 0x04), (2 + 34, 0x05)):
        bad_prefix = bytearray(canonical)
        bad_prefix[pos] = prefix
        with pytest.raises(InvalidMultisigRedeem):
            extract_multisig_quorum(script=bytes(bad_prefix))


def test_multisig_extract_rejects_duplicate_keys():
    k1 = bytes([0x02]) + bytes(31) + bytes([0x01])
    # Hand-assemble 2-of-2 with k1 twice (the builder rejects this, so
    # the raw bytes are constructed by hand).
    script = bytes([0x52, 0x21]) + k1 + bytes([0x21]) + k1 \
        + bytes([0x52, OP_CHECKMULTISIG])
    with pytest.raises(InvalidMultisigRedeem):
        extract_multisig_quorum(script=script)


def test_multisig_extract_rejects_body_length_mismatch():
    # OP_1 / OP_2 headers with only ONE key push between — the body
    # length does not match n = 2.
    k1 = bytes([0x02]) + bytes(31) + bytes([0x01])
    script = bytes([0x51, 0x21]) + k1 + bytes([0x52, OP_CHECKMULTISIG])
    with pytest.raises(InvalidMultisigRedeem):
        extract_multisig_quorum(script=script)


def test_multisig_script_sig_layout_pins_dummy_sigs_and_redeem():
    redeem = ms_redeem()
    sig_a = bytes(72)
    sig_b = bytes([0x31]) * 71
    script_sig = make_multisig_script_sig(redeem=redeem,
                                          sigs=[sig_a, sig_b])
    # OP_0 dummy first (R-MS-5): a single 0x00 byte.
    assert script_sig[0] == OP_0
    # sig pushes in script order…
    assert script_sig[1] == 72
    assert script_sig[2:74] == sig_a
    assert script_sig[74] == 71
    assert script_sig[75:146] == sig_b
    # …then the redeem push — 105 bytes > 75, so OP_PUSHDATA1.
    assert script_sig[146] == OP_PUSHDATA1
    assert script_sig[147] == len(redeem)
    assert script_sig[148:] == redeem
    assert len(script_sig) == 1 + 73 + 72 + 2 + 105


def test_multisig_script_sig_pushes_long_redeem_with_pushdata():
    # A 15-key redeem (513 bytes) must be pushed via OP_PUSHDATA2.
    distinct = [bytes([0x02]) + bytes(31) + bytes([i + 1])
                for i in range(15)]
    redeem = make_multisig_redeem_script(m=15, keys=distinct)
    sig = bytes(72)
    script_sig = make_multisig_script_sig(redeem=redeem, sigs=[sig])
    assert script_sig[0] == OP_0
    assert script_sig[1] == 72
    assert script_sig[74] == OP_PUSHDATA2
    assert script_sig[75:77] == (513).to_bytes(2, 'little')
    assert script_sig[77:] == redeem


def test_make_p2sh_lock_script_layout():
    h = b'\xab' * 20
    script = make_p2sh_lock_script(hash160=h)
    # OP_HASH160 <0x14> <20 bytes> OP_EQUAL — 23 bytes.
    assert script == bytes([0xa9, 0x14]) + h + bytes([0x87])
    assert len(script) == 23
    with pytest.raises(ValueError, match='hash160 must be 20 bytes'):
        make_p2sh_lock_script(hash160=b'\xab' * 19)


def test_redeem2p2sh_addr_kat():
    # The canonical fixture set addresses to the KAT value pinned from
    # the Rust oracle (see MS_ROWS below), a mainnet `3…` address that
    # decodes back to version 0x05 + hash160(redeem).
    addr = redeem2p2sh_addr(redeem=ms_redeem())
    assert addr.startswith('3')
    assert addr == '3M8uWojbqRXAmPA3UChxa2xpaGj293Nm9q'
    from yubtc.base58check import base58CheckDecode
    from yubtc.crypto import PREFIX_P2SH
    payload = base58CheckDecode(addr)
    assert payload[0] == PREFIX_P2SH
    assert payload[1:] == hash160(ms_redeem())
    # A different set addresses differently.
    other = make_multisig_redeem_script(m=1, keys=[ms_pub(7)])
    assert redeem2p2sh_addr(redeem=other) != addr


# --- 2. CompactSize pins (DEVIATIONS.md D-002) --------------------------


def test_tx_in_uses_compact_size_for_large_script_lengths():
    # A 253-byte script (the multisig scriptSig class) must encode its
    # length as the 3-byte CompactSize `fd fd 00` — a LEB128 encoder
    # would emit `fd 01`, which a Bitcoin node parses as a non-minimal
    # varint and rejects. Covers CIn (the direct-path encoder) and
    # PsbtTxIn (the PSBT container's) alike.
    script = b'\xab' * 253
    for txin in (CIn(txhash=b'\x11' * 32, n=0, script=script,
                     sequence=0xfffffffe),
                 PsbtTxIn(txhash=b'\x11' * 32, n=0, script=script,
                          sequence=0xfffffffe, witness=())):
        raw = txin.serialize()
        assert raw[36:39] == b'\xfd\xfd\x00'
        assert raw[39:39 + 253] == script
        # Scripts below 128 keep the single-byte length: pre-Phase-15
        # bytes are unchanged (LEB128 and CompactSize agree there).
    for small in (CIn(txhash=b'\x11' * 32, n=0, script=b'\x22' * 107,
                      sequence=0xfffffffe),
                  PsbtTxIn(txhash=b'\x11' * 32, n=0, script=b'\x22' * 107,
                           sequence=0xfffffffe, witness=())):
        assert small.serialize()[36] == 107


def test_compact_size_diverges_from_leb128_above_127():
    # The D-002 divergence, pinned: the two encodings agree below 0xfd
    # only; 253 is the first multisig scriptSig length past it.
    assert toVarInt(253) == b'\xfd\x01'
    assert compact_size(253) == b'\xfd\xfd\x00'
    assert toVarInt(126) == compact_size(126) == b'\x7e'


def test_wire_kat_carries_compact_size_scriptsig_length():
    # The e2e KAT wire (below) carries the finalized 253-byte multisig
    # scriptSig: bytes 41..44 are its CompactSize length `fd fd 00` --
    # the LEB128 encoder would have produced `fd 01` here.
    wire = bytes.fromhex(MS_ROWS['wire_hex'])
    assert len(MS_ROWS['wire_hex']) == 2 * len(wire)
    assert wire[41:44] == b'\xfd\xfd\x00'
    # CompactSize decoding of the length: `0xfd` prefix + u16 LE value.
    assert wire[41] == 0xfd
    assert int.from_bytes(wire[42:44], 'little') == 253


# --- 3. PSBT branches (Creator / Signer / Finalizer / Extractor) --------


def test_creator_p2sh_branch_writes_non_witness_utxo_and_redeem_script():
    psbt = ms_fixture_psbt()
    input_ = psbt.inputs[0]
    assert input_.non_witness_utxo is not None
    assert input_.witness_utxo is None
    assert input_.redeem_script == ms_redeem()
    # The typed field survives the wire round trip byte-for-byte
    # (REDEEM_SCRIPT 0x04 is W/R on the P2SH-multisig path).
    parsed = parse_psbt(data=serialize_psbt(psbt=psbt))
    assert parsed.inputs[0].redeem_script == ms_redeem()
    assert parsed == psbt


def test_creator_p2sh_branch_rejections():
    prev = ms_prev_tx()
    txhash = prev.id()
    unsigned = ms_unsigned_tx()
    spk = ms_p2sh_spk()

    # Non-canonical redeem script (R-MS-3) -> UnsupportedInputScript.
    with pytest.raises(UnsupportedInputScript):
        create_psbt(unsigned_tx=unsigned,
                    inputs=[CreateInput(amount=60000, script_pubkey=spk,
                                        prev_tx=prev, redeem_script=b'\x51')])
    # Redeem that hashes elsewhere -> UtxoMismatch.
    other = make_multisig_redeem_script(m=1, keys=[ms_pub(7)])
    with pytest.raises(UtxoMismatch):
        create_psbt(unsigned_tx=unsigned,
                    inputs=[CreateInput(amount=60000, script_pubkey=spk,
                                        prev_tx=prev, redeem_script=other)])
    # Missing prev tx -> IncompleteInput (a P2SH input is legacy).
    with pytest.raises(IncompleteInput) as ei:
        create_psbt(unsigned_tx=unsigned,
                    inputs=[CreateInput(amount=60000, script_pubkey=spk,
                                        prev_tx=None,
                                        redeem_script=ms_redeem())])
    assert ei.value.index == 0
    # Prev tx that hashes elsewhere -> UtxoMismatch.
    forged = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x99' * 32, n=0, script=b'',
                      sequence=0xffffffff, witness=()),),
        vout=(PsbtTxOut(amount=60000, script=spk),), locktime=0)
    assert forged.id() != txhash
    with pytest.raises(UtxoMismatch):
        create_psbt(unsigned_tx=unsigned,
                    inputs=[CreateInput(amount=60000, script_pubkey=spk,
                                        prev_tx=forged,
                                        redeem_script=ms_redeem())])


def test_creator_p2sh_without_redeem_script_keeps_witness_branch():
    # A redeem-less P2SH input is not the multisig branch: the Creator
    # falls through to the witness-form arm (WITNESS_UTXO, no
    # NON_WITNESS_UTXO), exactly like any other unsupported form.
    psbt = create_psbt(unsigned_tx=ms_unsigned_tx(),
                       inputs=[CreateInput(amount=60000,
                                           script_pubkey=ms_p2sh_spk(),
                                           prev_tx=ms_prev_tx(),
                                           redeem_script=None)])
    assert psbt.inputs[0].witness_utxo is not None
    assert psbt.inputs[0].non_witness_utxo is None
    assert psbt.inputs[0].redeem_script is None


def test_creator_witness_form_with_redeem_script_keeps_witness_branch():
    # The P2SH arm requires a P2SH scriptPubKey: a witness-form input
    # that carries a redeem script anyway still lands in the witness
    # branch (the `is_p2sh` half of the dispatch condition).
    from yubtc.script import make_p2wpkh_lock_script
    spk = bytes(make_p2wpkh_lock_script(hash160=hash160(ms_pub(3))))
    psbt = create_psbt(unsigned_tx=ms_unsigned_tx(),
                       inputs=[CreateInput(amount=60000, script_pubkey=spk,
                                           prev_tx=None,
                                           redeem_script=ms_redeem())])
    assert psbt.inputs[0].witness_utxo is not None
    assert psbt.inputs[0].redeem_script is None


def test_signer_p2sh_membership_signs_and_digest_uses_redeem():
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0)) is True
    input_ = psbt.inputs[0]
    assert len(input_.partial_sigs) == 1
    (pubkey, sig), = input_.partial_sigs
    assert pubkey == ms_pub(0)
    assert sig[-1] == PSBT_SIGHASH_ALL
    # The digest is the legacy SIGHASH_ALL preimage with
    # scriptCode = redeem: rebuild it independently and verify.
    preimage = _blanked_with(psbt=psbt, index=0,
                             script_code=ms_redeem()) + pack('<L', 1)
    from yubtc.crypto import sign_data
    assert sig == sign_data(privkey=ms_key(0), data=preimage) + b'\x01'


def _blanked_with(psbt, index, script_code):
    """The blanked stripped serialization with input `index`'s scriptSig
    slot set to `script_code` (the sighash preimage minus the type)."""
    blanked = PsbtTransaction(
        version=psbt.unsigned_tx.version,
        vin=tuple(v._replace(script=b'', witness=())
                  for v in psbt.unsigned_tx.vin),
        vout=psbt.unsigned_tx.vout, locktime=psbt.unsigned_tx.locktime)
    signed = blanked.vin[index]._replace(script=script_code)
    preimage = PsbtTransaction(
        version=blanked.version,
        vin=blanked.vin[:index] + (signed,) + blanked.vin[index + 1:],
        vout=blanked.vout, locktime=blanked.locktime)
    return preimage.serialize_stripped()


def test_signer_p2sh_non_member_returns_false():
    # A key outside the quorum: no signature, no error (BIP-174: the
    # Signer only adds data for inputs it can sign).
    foreign = ms_pub(9)
    assert foreign not in ms_redeem_keys()
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(9)) is False
    assert psbt.inputs[0].partial_sigs == []


def test_signer_p2sh_rejections():
    # Redeem script absent: the pre-Phase-15 refusal.
    psbt = ms_fixture_psbt()
    psbt.inputs[0].redeem_script = None
    with pytest.raises(UnsupportedInputScript):
        sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))

    # Redeem not canonical (R-MS-3): refused, not skipped.
    psbt = ms_fixture_psbt()
    psbt.inputs[0].redeem_script = b'\x51'
    with pytest.raises(UnsupportedInputScript):
        sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))

    # Redeem hash != scriptPubKey commitment (BIP-174 Data Signers
    # Check For).
    psbt = ms_fixture_psbt()
    psbt.inputs[0].redeem_script = make_multisig_redeem_script(
        m=2, keys=[ms_pub(0), ms_pub(1), ms_pub(5)])
    with pytest.raises(UtxoMismatch):
        sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))

    # NON_WITNESS_UTXO that hashes elsewhere.
    psbt = ms_fixture_psbt()
    psbt.inputs[0].non_witness_utxo = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x77' * 32, n=0, script=b'',
                      sequence=0xffffffff, witness=()),),
        vout=(PsbtTxOut(amount=60000, script=ms_p2sh_spk()),), locktime=0)
    assert psbt.inputs[0].non_witness_utxo.id() != ms_prev_tx().id()
    with pytest.raises(UtxoMismatch):
        sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))

    # A pinned sighash other than SIGHASH_ALL: refused (ОВ-8).
    psbt = ms_fixture_psbt()
    psbt.inputs[0].sighash_type = 0x02
    with pytest.raises(UnsupportedSighashType):
        sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))


def test_signer_p2sh_accepts_explicit_pinned_sighash_and_witness_utxo():
    # SIGHASH_TYPE present and equal to the pin: the check falls
    # through and the input signs (the `Some(1)` arm).
    psbt = ms_fixture_psbt()
    psbt.inputs[0].sighash_type = PSBT_SIGHASH_ALL
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0)) is True

    # A P2SH input backed by WITNESS_UTXO only (no NON_WITNESS_UTXO):
    # the prev-tx check is vacuous (its `None` arm) and the UTXO data
    # comes from the witness field — the legacy digest does not commit
    # amounts, so signing works.
    psbt = ms_fixture_psbt()
    psbt.inputs[0].non_witness_utxo = None
    psbt.inputs[0].witness_utxo = PsbtTxOut(amount=60000,
                                            script=ms_p2sh_spk())
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0)) is True
    assert len(psbt.inputs[0].partial_sigs) == 1


def test_signer_p2sh_idempotent():
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0)) is True
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0)) is True
    assert len(psbt.inputs[0].partial_sigs) == 1


def test_walk_signs_member_input_by_membership():
    # The ОВ-9 nonce walk finds the own key by *membership* in the
    # redeem script — the P2SH scriptPubKey is never "ours" by shape.
    psbt = ms_fixture_psbt()
    unsigned = sign_psbt(seed=SEED, passphrase='', kdf='yubtc', psbt=psbt)
    assert unsigned == []
    assert len(psbt.inputs[0].partial_sigs) == 1
    assert psbt.inputs[0].partial_sigs[0][0] == ms_pub(0)


def test_walk_leaves_foreign_quorums_unsigned():
    # A P2SH-multisig input whose redeem script contains none of our
    # keys: the walk must skip it (reported), not error.
    foreign = sorted(privkey2pubkey(
        seed2privkey(seed='foreign quorum {}'.format(i), nonce=0,
                     passphrase='', kdf='yubtc')) for i in range(3))
    redeem = make_multisig_redeem_script(m=2, keys=foreign)
    from yubtc.script import make_p2sh_lock_script
    spk = bytes(make_p2sh_lock_script(hash160=hash160(redeem)))
    prev = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x55' * 32, n=0, script=b'',
                      sequence=0xffffffff, witness=()),),
        vout=(PsbtTxOut(amount=60000, script=spk),), locktime=0)
    unsigned = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=prev.id(), n=0, script=b'',
                      sequence=0xfffffffe, witness=()),),
        vout=(PsbtTxOut(amount=50000, script=ms_dst_spk()),), locktime=0)
    psbt = create_psbt(unsigned_tx=unsigned,
                       inputs=[CreateInput(amount=60000, script_pubkey=spk,
                                           prev_tx=prev,
                                           redeem_script=redeem)])
    assert sign_psbt(seed=SEED, passphrase='', kdf='yubtc', psbt=psbt) == [0]
    assert psbt.inputs[0].partial_sigs == []


def test_finalizer_p2sh_success_clears_intermediates():
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    sigs_by_key = dict(psbt.inputs[0].partial_sigs)
    finalize_psbt_input(psbt=psbt, index=0)
    input_ = psbt.inputs[0]
    script_sig = input_.final_scriptsig
    assert script_sig is not None
    # Layout: OP_0 ‖ push(sig ‖ 0x01)×2 ‖ push(redeem), signatures in
    # *script* key order (R-MS-4): the present members, taken in the
    # order the redeem script lists them.
    assert script_sig[0] == OP_0
    pushes = _decode_pushes(script_sig[1:])
    assert len(pushes) == 3
    keys_in_script_order = ms_redeem_keys()
    present = [k for k in keys_in_script_order if k in sigs_by_key]
    assert len(present) == 2
    assert pushes[0] == sigs_by_key[present[0]]
    assert pushes[1] == sigs_by_key[present[1]]
    assert pushes[2] == ms_redeem()
    assert pushes[0][-1] == pushes[1][-1] == PSBT_SIGHASH_ALL
    # Intermediates out, UTXOs stay (BIP-174 mandate).
    assert input_.partial_sigs == []
    assert input_.sighash_type is None
    assert input_.redeem_script is None
    assert input_.witness_script is None
    assert input_.non_witness_utxo is not None


def _decode_pushes(script):
    """Decode a script of concatenated pushes into its payload list
    (single-opcode and PUSHDATA1/2 forms; test-side helper)."""
    pushes = []
    pos = 0
    while pos < len(script):
        head = script[pos]
        pos += 1
        if head <= 0x4b:
            pushes.append(script[pos:pos + head])
            pos += head
        elif head == OP_PUSHDATA1:
            n = script[pos]
            pushes.append(script[pos + 1:pos + 1 + n])
            pos += 1 + n
        else:
            assert head == OP_PUSHDATA2
            n = int.from_bytes(script[pos:pos + 2], 'little')
            pushes.append(script[pos + 2:pos + 2 + n])
            pos += 2 + n
    return pushes


def test_finalizer_p2sh_incomplete_cases():
    # Fewer than M member signatures: IncompleteInput, input untouched.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    with pytest.raises(IncompleteInput) as ei:
        finalize_psbt_input(psbt=psbt, index=0)
    assert ei.value.index == 0
    assert psbt.inputs[0].final_scriptsig is None
    assert len(psbt.inputs[0].partial_sigs) == 1

    # A P2SH input is finalizable only with a known redeem script.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    psbt.inputs[0].redeem_script = None
    with pytest.raises(IncompleteInput):
        finalize_psbt_input(psbt=psbt, index=0)

    # A signature whose sighash byte disagrees blocks the input
    # (BIP-174 MUST) — even when the quorum is otherwise complete.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    psbt.inputs[0].partial_sigs[0] = (
        psbt.inputs[0].partial_sigs[0][0],
        psbt.inputs[0].partial_sigs[0][1][:-1] + b'\x02')
    with pytest.raises(IncompleteInput):
        finalize_psbt_input(psbt=psbt, index=0)


def test_finalizer_p2sh_sighash_pin_and_rejections():
    # A pinned SIGHASH_TYPE other than SIGHASH_ALL blocks the input.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    psbt.inputs[0].sighash_type = 0x02
    with pytest.raises(IncompleteInput):
        finalize_psbt_input(psbt=psbt, index=0)

    # SIGHASH_TYPE present and equal to the pin: the `Some(1)` arm
    # falls through and the input finalizes.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    psbt.inputs[0].sighash_type = PSBT_SIGHASH_ALL
    finalize_psbt_input(psbt=psbt, index=0)
    assert psbt.inputs[0].final_scriptsig is not None

    # A non-canonical redeem script is refused, not merely left
    # incomplete (R-MS-3 — yubtc does not finalize foreign forms).
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    psbt.inputs[0].redeem_script = b'\x52\x51'
    with pytest.raises(UnsupportedInputScript):
        finalize_psbt_input(psbt=psbt, index=0)

    # A redeem script hashing elsewhere: UtxoMismatch.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    psbt.inputs[0].redeem_script = make_multisig_redeem_script(
        m=2, keys=[ms_pub(0), ms_pub(1), ms_pub(5)])
    with pytest.raises(UtxoMismatch):
        finalize_psbt_input(psbt=psbt, index=0)


def test_finalizer_p2sh_greedy_any_m_of_n_and_tail_truncation():
    # CHECKMULTISIG matching is greedy: *any* M distinct member keys
    # can carry the spend. Sign all three; the finalizer takes the
    # first M in script-key order and deterministically drops the
    # tail.
    psbt = ms_fixture_psbt()
    for nonce in (0, 1, 2):
        assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(nonce))
    assert len(psbt.inputs[0].partial_sigs) == 3
    sigs_by_key = dict(psbt.inputs[0].partial_sigs)
    finalize_psbt_input(psbt=psbt, index=0)
    pushes = _decode_pushes(psbt.inputs[0].final_scriptsig[1:])
    keys_in_script_order = ms_redeem_keys()
    assert len(pushes) == 3  # two sigs + redeem
    assert pushes[0] == sigs_by_key[keys_in_script_order[0]]
    assert pushes[1] == sigs_by_key[keys_in_script_order[1]]
    assert pushes[2] == ms_redeem()
    # And a different quorum subset (keys 0 and 2) finalizes too.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(2))
    finalize_psbt_input(psbt=psbt, index=0)
    assert psbt.inputs[0].final_scriptsig is not None


def test_finalizer_p2sh_arrival_order_irrelevant():
    # R-MS-4: the final scriptSig follows the script's key order,
    # never the PARTIAL_SIG arrival order.
    a = ms_fixture_psbt()
    assert sign_psbt_input(psbt=a, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=a, index=0, privkey=ms_key(1))
    b = ms_fixture_psbt()
    assert sign_psbt_input(psbt=b, index=0, privkey=ms_key(1))
    assert sign_psbt_input(psbt=b, index=0, privkey=ms_key(0))
    finalize_psbt_input(psbt=a, index=0)
    finalize_psbt_input(psbt=b, index=0)
    assert a.inputs[0].final_scriptsig == b.inputs[0].final_scriptsig


def test_finalize_psbt_ignores_unsupported_and_incomplete_inputs():
    # The whole-PSBT Finalizer is per-input and ignores every
    # per-input error (the Rust oracle's `let _ =`), including the
    # Phase 15 UnsupportedInputScript/UtxoMismatch arms.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    # Incomplete (1 of 2) AND a foreign redeem field on top: both
    # error classes are swallowed, the input stays untouched.
    psbt.inputs[0].redeem_script = b'\x51'
    finalize_psbt(psbt=psbt)
    assert psbt.inputs[0].final_scriptsig is None
    assert len(psbt.inputs[0].partial_sigs) == 1


def test_extractor_p2sh_rules():
    # Complete quorum: the FINAL_SCRIPTSIG becomes the input's
    # scriptSig; no witness section appears (legacy spend).
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    finalize_psbt(psbt=psbt)
    tx = extract_transaction(psbt=psbt)
    assert tx.vin[0].script == psbt.inputs[0].final_scriptsig
    assert not tx.vin[0].witness
    assert not tx.has_witness()

    # A P2SH input without FINAL_SCRIPTSIG is NotFinalized.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    with pytest.raises(NotFinalized):
        extract_transaction(psbt=psbt)

    # …and one carrying a witness stack is IncompleteInput (nested
    # SegWit stays rejected — BIP-141 / Phase 13).
    psbt.inputs[0].final_scriptwitness = b'\x02\x00\x21' + ms_pub(0)
    with pytest.raises(IncompleteInput) as ei:
        extract_transaction(psbt=psbt)
    assert ei.value.index == 0


# --- 4. 2-of-3 e2e with an independent CHECKMULTISIG evaluator ----------
#
# The verifier deliberately shares no code with yubtc: the wire tx is
# parsed with a local CompactSize reader, the legacy sighash preimage
# is re-encoded field-by-field with a local writer, the
# CHECKMULTISIG stack semantics (empty dummy -> greedy signature-to-key
# matching in script-key order) are implemented locally, and every
# signature is ECDSA-verified with coincurve over the recomputed
# digest (hasher=None = the prehash, mirroring k256's
# PrehashVerifier).


def _read_cs(data: bytes, pos: int):
    prefix = data[pos]
    if prefix <= 0xfc:
        return prefix, pos + 1
    if prefix == 0xfd:
        return int.from_bytes(data[pos + 1:pos + 3], 'little'), pos + 3
    if prefix == 0xfe:
        return int.from_bytes(data[pos + 1:pos + 5], 'little'), pos + 5
    return int.from_bytes(data[pos + 1:pos + 9], 'little'), pos + 9


def _write_cs(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    return b'\xfd' + n.to_bytes(2, 'little')


def _local_parse_tx(wire: bytes):
    pos = 0
    version = int.from_bytes(wire[pos:pos + 4], 'little')
    pos += 4
    if wire[pos] == 0x00 and wire[pos + 1] == 0x01:
        raise ValueError('witness layout not expected in this fixture')
    n_vin, pos = _read_cs(wire, pos)
    vin = []
    for _ in range(n_vin):
        txid = wire[pos:pos + 32]
        pos += 32
        vout = int.from_bytes(wire[pos:pos + 4], 'little')
        pos += 4
        slen, pos = _read_cs(wire, pos)
        script = wire[pos:pos + slen]
        pos += slen
        seq = int.from_bytes(wire[pos:pos + 4], 'little')
        pos += 4
        vin.append((txid, vout, script, seq))
    n_vout, pos = _read_cs(wire, pos)
    vouts = []
    for _ in range(n_vout):
        amount = int.from_bytes(wire[pos:pos + 8], 'little')
        pos += 8
        slen, pos = _read_cs(wire, pos)
        vouts.append((amount, wire[pos:pos + slen]))
        pos += slen
    locktime = int.from_bytes(wire[pos:pos + 4], 'little')
    pos += 4
    if pos != len(wire):
        raise ValueError('trailing bytes')
    return version, vin, vouts, locktime


def _independent_ms_digest(wire: bytes, redeem: bytes) -> bytes:
    """The legacy SIGHASH_ALL digest of input 0 with
    scriptCode = redeem, re-encoded independently of yubtc."""
    version, vin, vouts, locktime = _local_parse_tx(wire)
    if len(vin) != 1:
        raise ValueError('fixture expects a single input')
    txid, vout, _script, seq = vin[0]
    pre = (version.to_bytes(4, 'little')
           + _write_cs(1)
           + txid + vout.to_bytes(4, 'little')
           + _write_cs(len(redeem)) + redeem
           + seq.to_bytes(4, 'little')
           + _write_cs(len(vouts)))
    for amount, spk in vouts:
        pre += amount.to_bytes(8, 'little') + _write_cs(len(spk)) + spk
    pre += (locktime.to_bytes(4, 'little')
            + (1).to_bytes(4, 'little'))  # SIGHASH_ALL
    return hashlib.sha256(hashlib.sha256(pre).digest()).digest()


def _independent_checkmultisig_verify(wire: bytes, expected_keys: list):
    """Evaluate a completed P2SH-multisig spend the way the consensus
    interpreter would. Returns an error string, or None on success."""
    import coincurve
    try:
        version, vin, vouts, locktime = _local_parse_tx(wire)
    except ValueError as e:
        return 'wire parse: {}'.format(e)
    _version, _vout, script_sig, _seq = vin[0]
    pushes, ops = [], []
    pos = 0
    while pos < len(script_sig):
        head = script_sig[pos]
        pos += 1
        if head == 0x00:
            pushes.append(b'')
        elif head <= 0x4b:
            pushes.append(script_sig[pos:pos + head])
            pos += head
        elif head == 0x4c:
            n = script_sig[pos]
            pushes.append(script_sig[pos + 1:pos + 1 + n])
            pos += 1 + n
        elif head == 0x4d:
            n = int.from_bytes(script_sig[pos:pos + 2], 'little')
            pushes.append(script_sig[pos + 2:pos + 2 + n])
            pos += 2 + n
        else:
            ops.append(head)
    # The OP_0 dummy pushes an EMPTY byte string: in the canonical
    # form there are no bare opcodes at all, the first push is empty
    # (the dummy), then M signatures, then the redeem script push.
    if ops:
        return 'unexpected bare opcodes {} in the scriptSig'.format(ops)
    if len(pushes) < 3:
        return ('scriptSig needs a dummy, at least one signature, and '
                'the redeem')
    if pushes[0]:
        return ('the dummy element must be empty (BIP-147), got {} '
                'bytes'.format(len(pushes[0])))
    redeem = pushes[-1]
    sigs = pushes[1:-1]

    # Redeem script: OP_m ‖ (0x21‖key)×N ‖ OP_n ‖ 0xae.
    if len(redeem) < 3 + 34 or redeem[-1] != 0xae:
        return 'redeem is not a CHECKMULTISIG script'
    if redeem[0] < 0x51 or redeem[-2] < 0x51:
        return 'quorum counters must be OP_1..=OP_16'
    m = redeem[0] - 0x50
    n = redeem[-2] - 0x50
    if m > n:
        return 'm must not exceed n'
    if len(redeem) != 3 + 34 * n:
        return 'redeem body does not match N pushes'
    keys = []
    for i in range(n):
        s = 1 + i * 34
        if redeem[s] != 0x21:
            return 'non-canonical key push'
        keys.append(redeem[s + 1:s + 34])
    if keys != list(expected_keys):
        return 'redeem keys do not match the expected quorum'
    if len(sigs) != m:
        return 'expected {} signatures, got {}'.format(m, len(sigs))

    # Digest + greedy CHECKMULTISIG matching in script-key order.
    digest = _independent_ms_digest(wire, redeem)
    key_idx = 0
    for j, sig in enumerate(sigs):
        if not sig or sig[-1] != 0x01:
            return 'signature {} lacks the SIGHASH_ALL suffix'.format(j)
        der = sig[:-1]
        matched = False
        while key_idx < len(keys):
            vk = coincurve.PublicKey(keys[key_idx])
            key_idx += 1
            if vk.verify(der, digest, hasher=None):
                matched = True
                break
        if not matched:
            return ('signature {} matches no remaining script key'
                    .format(j))
    return None


def test_e2e_two_signers_combine_finalize_extract_independent_verify():
    # 1. Creator.
    psbt_a = ms_fixture_psbt()
    # 2. Signer A — the seed-based walk finds its key by *membership*.
    assert sign_psbt(seed=SEED, passphrase='', kdf='yubtc', psbt=psbt_a) \
        == []
    assert len(psbt_a.inputs[0].partial_sigs) == 1
    # 3. Signer B — direct primitive on the second quorum key.
    psbt_b = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt_b, index=0, privkey=ms_key(1))
    # 4. Combiner: A ∪ B.
    combined = combine_psbt(psbt=psbt_a, other=psbt_b)
    assert len(combined.inputs[0].partial_sigs) == 2
    # 5. Finalizer: 2-of-3 quorum complete.
    finalize_psbt(psbt=combined)
    assert combined.inputs[0].final_scriptsig is not None
    # 6. Extractor: the wire transaction.
    tx = extract_transaction(psbt=combined)
    wire = tx.serialize_wire()
    # 7. Independent consensus-equivalent verification.
    assert _independent_checkmultisig_verify(wire, ms_redeem_keys()) \
        is None
    # The finalized txid pin from the Rust oracle (KAT cross-check).
    assert tx.id().hex() == MS_ROWS['txid']


def test_scriptsig_mutations_fail_independent_verification():
    # A complete spend, decomposed for mutation.
    psbt = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(1))
    sigs = [sig for _key, sig in psbt.inputs[0].partial_sigs]
    redeem = ms_redeem()
    keys = ms_redeem_keys()
    finalize_psbt_input(psbt=psbt, index=0)
    base_tx = extract_transaction(psbt=psbt)

    def wire_with(script_sig: bytes) -> bytes:
        mutated = base_tx._replace(
            vin=(base_tx.vin[0]._replace(script=script_sig),))
        return mutated.serialize_wire()

    # Mutation 1: non-empty dummy (BIP-147 NULLDUMMY violation).
    bad_dummy = b'\x01\x00' + push_data(data=sigs[0]) \
        + push_data(data=sigs[1]) + push_data(data=redeem)
    err = _independent_checkmultisig_verify(wire_with(bad_dummy), keys)
    assert err is not None and 'dummy' in err

    # Mutation 2: signatures in the wrong (non-script) order.
    swapped = make_multisig_script_sig(redeem=redeem,
                                       sigs=[sigs[1], sigs[0]])
    err = _independent_checkmultisig_verify(wire_with(swapped), keys)
    assert err is not None and 'matches no remaining script key' in err

    # Mutation 3: a signature by a foreign key over the same digest —
    # the greedy match runs out of keys (signed independently with
    # coincurve).
    digest = _independent_ms_digest(wire_with(make_multisig_script_sig(
        redeem=redeem, sigs=[sigs[0], sigs[1]])), redeem)
    import coincurve
    foreign_sig = coincurve.PrivateKey(ms_key(7).secret).sign(
        digest, hasher=None) + b'\x01'
    foreign = make_multisig_script_sig(redeem=redeem,
                                       sigs=[sigs[0], foreign_sig])
    err = _independent_checkmultisig_verify(wire_with(foreign), keys)
    assert err is not None and 'matches no remaining script key' in err

    # Mutation 4: the dummy dropped entirely (no OP_0 empty push).
    no_dummy = push_data(data=sigs[0]) + push_data(data=sigs[1]) \
        + push_data(data=redeem)
    err = _independent_checkmultisig_verify(wire_with(no_dummy), keys)
    assert err is not None and 'dummy' in err

    # Mutation 5: a truncated scriptSig — the dummy plus one sig is
    # structurally well-formed but one signature short of the quorum.
    short = push_data(data=b'') + push_data(data=sigs[0]) \
        + push_data(data=redeem)
    err = _independent_checkmultisig_verify(wire_with(short), keys)
    assert err is not None and 'expected 2 signatures, got 1' in err


def test_independent_digest_rejects_unusable_wire_and_scales():
    # A long output script forces the local CS writer's `0xfd`
    # escalation branch inside the preimage; the digest must differ
    # from the same tx with a short output (the writer is honest).
    vin = (PsbtTxIn(txhash=b'\x66' * 32, n=0, script=b'',
                    sequence=0xfffffffe, witness=()),)
    long_out = PsbtTransaction(version=2, vin=vin,
                               vout=(PsbtTxOut(amount=1000,
                                               script=b'\x51' * 300),),
                               locktime=0)
    short_out = long_out._replace(vout=(PsbtTxOut(amount=1000,
                                                  script=b'\x51'),))
    redeem = ms_redeem()
    long_wire = long_out.serialize_wire()
    short_wire = short_out.serialize_wire()
    d_long = _independent_ms_digest(long_wire, redeem)
    d_short = _independent_ms_digest(short_wire, redeem)
    assert d_long != d_short
    # Unusable wire: a witness layout header is refused by the local
    # parser (the fixtures are legacy spends); truncation and garbage
    # are likewise rejected before any digest is computed.
    with pytest.raises(ValueError, match='witness layout'):
        _independent_ms_digest(b'\x02\x00\x00\x00\x00\x01', redeem)
    with pytest.raises(ValueError, match='trailing'):
        _independent_ms_digest(short_wire + b'\x00', redeem)
    with pytest.raises((ValueError, IndexError)):
        _independent_ms_digest(b'', redeem)


# --- 5. Wallet quorum surface -------------------------------------------


def wallet_pubkey(nonce: int) -> bytes:
    return privkey2pubkey(seed2privkey(seed=WALLET_SEED, nonce=nonce,
                                       passphrase='', kdf='yubtc'))


def wallet_fixture_quorum():
    """The 2-of-3 fixture quorum: own key at nonce 0, cosigners at
    nonces 1-2 of the same fixture seed (mirrors the Rust
    `ms_fixture_quorum`)."""
    keys = [wallet_pubkey(1), wallet_pubkey(2)]
    addr, redeem = ms_create_address(n=3, m=2,
                                     keys=[wallet_pubkey(0)] + keys)
    script = bytes(make_p2sh_lock_script(hash160=hash160(redeem)))
    return keys, addr, redeem, script


class MsMockBackend:
    """In-memory backend serving canned UTXOs and raw transactions for
    the multisig Creator tests (mirrors the Rust MsMockBackend)."""

    def __init__(self, unspent=(), raw=None, fail_unspent=False):
        self.unspent = list(unspent)
        self.raw = dict(raw or {})
        self.fail_unspent = fail_unspent
        self.broadcasts = []

    def get_unspent(self, address, **kwargs):
        if self.fail_unspent:
            raise RuntimeError('mock failure')
        return list(self.unspent)

    def get_info(self, address, **kwargs):
        return {'total_received': 0}

    def send_tx(self, rawtx, **kwargs):
        self.broadcasts.append(rawtx)

    def raw_transaction(self, txid, **kwargs):
        if txid not in self.raw:
            raise RuntimeError('no raw tx {}'.format(txid))
        return self.raw[txid]


def wire_prev_tx(script: bytes, txhash: bytes) -> PsbtTransaction:
    """A prev tx paying 60_000 sat to `script` from outpoint `txhash`."""
    return PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=txhash, n=0, script=b'',
                      sequence=0xffffffff, witness=()),),
        vout=(PsbtTxOut(amount=60000, script=script),), locktime=0)


def backend_for(prev: PsbtTransaction, script: bytes,
                confirmations: int = 10, raw=None, **kwargs) -> MsMockBackend:
    utxo = {'tx_hash': prev.id().hex(), 'tx_output_n': 0,
            'value': 60000, 'script': script.hex(),
            'confirmations': confirmations}
    if raw is None:
        raw = {prev.id().hex(): prev.serialize_wire().hex()}
    return MsMockBackend(unspent=[utxo], raw=raw, **kwargs)


def test_ms_error_hierarchy_mirrors_the_rust_enum():
    # Every MsError variant is an MsError subclass with the Rust
    # thiserror message; payload-less variants carry their default.
    for variant in (QuorumBounds(), DuplicateKey(), ForeignWif(),
                    NotAParticipant()):
        assert isinstance(variant, MsError)
    assert str(QuorumBounds()) == 'quorum out of bounds: need 1 ≤ M ≤ N ≤ 15'
    assert str(DuplicateKey()) == 'duplicate key in the quorum'
    assert str(ForeignWif()) == \
        'WIF does not match the key derived at this nonce'
    assert str(NotAParticipant()) == \
        'own key is not a participant of this quorum'
    assert str(KeyCountMismatch(expected=3, got=2)) == \
        'key count mismatch: expected exactly 3 keys, got 2'


def wallet_dst() -> str:
    """A valid bech32 destination (fixture key's native address)."""
    return pubkey2segwit_addr(pubkey=wallet_pubkey(8))


def test_ms_create_address_builds_sorted_redeem_and_p2sh_address():
    keys = [wallet_pubkey(2), wallet_pubkey(0), wallet_pubkey(1)]
    addr, redeem = ms_create_address(n=3, m=2, keys=keys)
    # The redeem is canonical, sorted, and hashes to the address.
    m, script_keys = extract_multisig_quorum(script=redeem)
    assert m == 2
    # Script order is the BIP-67 byte sort of the three keys.
    assert script_keys == sorted([wallet_pubkey(0), wallet_pubkey(1),
                                  wallet_pubkey(2)])
    assert addr == redeem2p2sh_addr(redeem=redeem)
    # The address decodes as P2SH carrying hash160(redeem).
    from yubtc.base58check import base58CheckDecode
    from yubtc.crypto import PREFIX_P2SH
    payload = base58CheckDecode(addr)
    assert payload[0] == PREFIX_P2SH
    assert payload[1:] == hash160(redeem)


def test_ms_create_address_validation_errors():
    keys = [wallet_pubkey(0), wallet_pubkey(1)]
    # Count mismatch.
    with pytest.raises(KeyCountMismatch) as ei:
        ms_create_address(n=3, m=2, keys=keys)
    assert (ei.value.expected, ei.value.got) == (3, 2)
    with pytest.raises(KeyCountMismatch):
        ms_create_address(n=1, m=1, keys=keys)
    # Bounds: m = 0, m > n, n > 15.
    for n, m, ks in ((2, 0, keys), (2, 3, keys)):
        with pytest.raises(QuorumBounds):
            ms_create_address(n=n, m=m, keys=ks)
    sixteen = [bytes([0x02]) + bytes(31) + bytes([i + 1])
               for i in range(16)]
    with pytest.raises(QuorumBounds):
        ms_create_address(n=16, m=16, keys=sixteen)
    # Duplicates.
    with pytest.raises(DuplicateKey):
        ms_create_address(n=2, m=1, keys=[wallet_pubkey(0),
                                          wallet_pubkey(0)])
    # A key outside the 33-byte canonical shape cannot build a redeem
    # script: the wallet maps the builder failure onto QuorumBounds
    # (the quorum is outside the spendable envelope).
    with pytest.raises(QuorumBounds):
        ms_create_address(n=2, m=1, keys=[b'\x02' * 32, b'\x03' * 32])


def test_ms_create_address_invariant_under_key_permutation_many_orders():
    # R-MS-4 pin: the same (N, M, set) in any argument order gives the
    # same address and redeem — exhaustive over the 4-key fixture
    # (24 permutations) plus 97 deterministic LCG shuffles (the Rust
    # test's sweep).
    keys = [wallet_pubkey(i) for i in range(4)]
    canon_addr, canon_redeem = ms_create_address(n=4, m=3, keys=keys)
    for perm in itertools.permutations(keys):
        addr, redeem = ms_create_address(n=4, m=3, keys=list(perm))
        assert (addr, redeem) == (canon_addr, canon_redeem)
    order = list(keys)
    state = 0x9e3779b97f4a7c15
    for _ in range(97):
        for i in range(len(order) - 1, 0, -1):
            state = (state * 6364136223846793005
                     + 1442695040888963407) % (1 << 64)
            j = (state >> 33) % (i + 1)
            order[i], order[j] = order[j], order[i]
        addr, redeem = ms_create_address(n=4, m=3, keys=order)
        assert (addr, redeem) == (canon_addr, canon_redeem)


def test_ms_own_key_is_the_legacy_form_at_the_nonce():
    # The own key equals the `TPrivKey` legacy derivation
    # (`dumpprivkey -n X` — R-MS-6/ОВ-10), for the cascade KDF…
    own = ms_own_pubkey(seed='own-key-form', nonce=4, passphrase='')
    direct = privkey2pubkey(seed2privkey(seed='own-key-form', nonce=4,
                                         passphrase='', kdf='yubtc'))
    assert own == direct
    # …for a different nonce a different key (the derivation is
    # nonce-parameterised), and the privkey/pubkey helpers agree.
    own4 = ms_own_pubkey(seed='own-key-form', nonce=4, passphrase='')
    own5 = ms_own_pubkey(seed='own-key-form', nonce=5, passphrase='')
    assert own4 != own5
    assert ms_own_privkey(seed='own-key-form', nonce=4,
                          passphrase='').secret == ms_key(4,
                                                          'own-key-form') \
        .secret


def test_ms_own_key_pbkdf2_uses_the_legacy_leaf():
    # …and for pbkdf2 the m/44' leaf (BIP-44 legacy), not the
    # native/taproot ones.
    mnemonic = ('abandon abandon abandon abandon abandon abandon '
                'abandon abandon abandon abandon about')
    own = ms_own_pubkey(seed=mnemonic, nonce=0, passphrase='x',
                        kdf='pbkdf2')
    legacy = privkey2pubkey(seed2privkey(seed=mnemonic, nonce=0,
                                         passphrase='x', kdf='pbkdf2',
                                         addr_type='legacy'))
    assert own == legacy
    native = privkey2pubkey(seed2privkey(seed=mnemonic, nonce=0,
                                         passphrase='x', kdf='pbkdf2',
                                         addr_type='native'))
    assert own != native


def test_ms_own_privkey_reports_derivation_failures():
    # Empty seed.
    with pytest.raises(ValueError, match='seed cannot be empty'):
        ms_own_privkey(seed='', nonce=0, passphrase='')
    # Non-yubtc KDF without a passphrase.
    with pytest.raises(Exception, match='passphrase required'):
        ms_own_privkey(seed='derivation-failures', nonce=0, passphrase='',
                       kdf='pbkdf2')
    # yubtc cascade with a (rejected) passphrase.
    with pytest.raises(Exception, match='incompatible'):
        ms_own_privkey(seed='derivation-failures', nonce=0, passphrase='x',
                       kdf='yubtc')
    # The pubkey helper forwards the underlying derivation error.
    with pytest.raises(ValueError, match='seed cannot be empty'):
        ms_own_pubkey(seed='', nonce=0, passphrase='')


def test_ms_wif_own_key_accepts_only_the_derived_secret():
    derived = ms_key(0, WALLET_SEED)
    wif = privkey2privwif(privkey=derived)
    assert ms_wif_own_key(derived=derived, wif=wif) \
        == wallet_pubkey(0)
    # A foreign (valid) WIF — different key — is rejected.
    foreign = privkey2privwif(privkey=ms_key(9, WALLET_SEED))
    with pytest.raises(ForeignWif):
        ms_wif_own_key(derived=derived, wif=foreign)
    # Garbage is rejected.
    for garbage in ('not-a-wif', ''):
        with pytest.raises(ForeignWif):
            ms_wif_own_key(derived=derived, wif=garbage)


def test_ms_select_utxos_takes_the_smallest_reaching_prefix():
    def utxo(i, value):
        return {'tx_hash': '{:064x}'.format(i), 'tx_output_n': 0,
                'value': value, 'script': 'a9', 'confirmations': 6}

    utxos = [utxo(1, 30_000), utxo(2, 20_000), utxo(3, 50_000)]
    # The first two UTXOs cover 50_000 — the walk stops there.
    picked = ms_select_utxos(utxos=utxos, target=50_000)
    assert [u['value'] for u in picked] == [30_000, 20_000]
    # Unreachable target selects everything.
    assert len(ms_select_utxos(utxos=utxos, target=1 << 63)) == 3
    # Drain (no target) selects everything.
    assert len(ms_select_utxos(utxos=utxos, target=None)) == 3
    # Empty input -> empty selection.
    assert ms_select_utxos(utxos=[], target=1) == []


def test_ms_create_psbt_builds_and_signs_over_a_mock_backend():
    _keys, _addr, redeem, script = wallet_fixture_quorum()
    prev = wire_prev_tx(script, b'\x77' * 32)
    backend = backend_for(prev, script)
    dst = wallet_dst()

    outcome = ms_create_psbt(seed=WALLET_SEED, passphrase='',
                             backend=backend, dst=dst, amount=50_000,
                             n=3, m=2,
                             keys=[wallet_pubkey(1), wallet_pubkey(2)],
                             own_nonce=0, confirmations=6, feekb=1000,
                             fee=0)
    from yubtc.psbt import from_base64
    psbt = from_base64(s=outcome.psbt_b64)
    # The PSBT carries the quorum input, its redeem script and exactly
    # one partial signature — the own key's.
    assert len(psbt.inputs) == 1
    assert psbt.inputs[0].redeem_script == redeem
    assert len(psbt.inputs[0].partial_sigs) == 1
    assert psbt.inputs[0].partial_sigs[0][0] == wallet_pubkey(0)
    # Fee arithmetic: fee + amount + cashback == 60_000 and the
    # cashback went back to the QUORUM address.
    assert outcome.fee + outcome.amount + outcome.cashback == 60_000
    assert psbt.unsigned_tx.vout[0].script == script
    assert outcome.fee > 0
    # Completion: the second cosigner (nonce 1 of the same fixture
    # seed) signs, the quorum finalizes and extracts.
    assert sign_psbt_input(psbt=psbt, index=0,
                           privkey=ms_key(1, WALLET_SEED))
    finalize_psbt(psbt=psbt)
    tx = extract_transaction(psbt=psbt)
    assert len(tx.vin[0].script) > len(redeem)
    assert not tx.vin[0].witness


def test_ms_create_psbt_requires_participation_and_valid_quorum():
    _keys, _addr, _redeem, script = wallet_fixture_quorum()
    prev = wire_prev_tx(script, b'\x78' * 32)
    backend = backend_for(prev, script)
    dst = wallet_dst()
    cosigners = [wallet_pubkey(1), wallet_pubkey(2)]

    # No own nonce -> NotAParticipant (never builds a foreign quorum's
    # spend).
    with pytest.raises(NotAParticipant):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, n=3, m=2, keys=cosigners,
                       own_nonce=None, confirmations=6, feekb=1000,
                       fee=0)

    # R-MS-1 pins: N, M and the own nonce are entered explicitly —
    # the signature carries no value default for n/m (`NotNone`
    # sentinel; `own_nonce` accepts an explicit None only), and
    # omission is a usage error, never a prompt-substituted value.
    import inspect
    from yubtc import wallet as wallet_mod
    from yubtc.util import NotNone
    sig = inspect.signature(wallet_mod.ms_create_psbt.__wrapped__)
    assert sig.parameters['n'].default is NotNone
    assert sig.parameters['m'].default is NotNone
    assert sig.parameters['own_nonce'].default is None
    with pytest.raises(TypeError, match='n not set'):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, m=2, keys=cosigners,
                       own_nonce=0, confirmations=6, feekb=1000, fee=0)
    with pytest.raises(TypeError, match='m not set'):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, n=3, keys=cosigners,
                       own_nonce=0, confirmations=6, feekb=1000, fee=0)

    # n = 16 (15 cosigners + own) -> QuorumBounds.
    fifteen = [bytes([0x02]) + bytes(31) + bytes([i + 1])
               for i in range(15)]
    with pytest.raises(QuorumBounds):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, n=16, m=16, keys=fifteen,
                       own_nonce=0, confirmations=6, feekb=1000, fee=0)

    # Confirmations filter: the only UTXO has 10 confs, asking for 50
    # leaves no funds -> make_vout refuses (AmountExceedsInput).
    with pytest.raises(ValueError, match=r'amount \+ fee exceeds input'):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, n=3, m=2, keys=cosigners,
                       own_nonce=0, confirmations=50, feekb=1000, fee=0)


def test_ms_create_psbt_surfaces_network_and_raw_tx_failures():
    _keys, _addr, _redeem, script = wallet_fixture_quorum()
    dst = wallet_dst()
    cosigners = [wallet_pubkey(1), wallet_pubkey(2)]

    # UTXO fetch failure propagates.
    backend = MsMockBackend(fail_unspent=True)
    with pytest.raises(RuntimeError, match='mock failure'):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, n=3, m=2, keys=cosigners,
                       own_nonce=0, confirmations=6, feekb=1000, fee=0)

    # A UTXO whose raw prev tx is missing -> the backend's error
    # propagates (explicit fee: the loop is skipped, the Creator's raw
    # fetch fails).
    prev = wire_prev_tx(script, b'\x79' * 32)
    backend = backend_for(prev, script, raw={})
    with pytest.raises(RuntimeError, match='no raw tx'):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, n=3, m=2, keys=cosigners,
                       own_nonce=0, confirmations=6, feekb=1000,
                       fee=1000)

    # Garbage raw prev tx -> ValueError naming the tx.
    backend = MsMockBackend(
        unspent=[{'tx_hash': prev.id().hex(), 'tx_output_n': 0,
                  'value': 60000, 'script': script.hex(),
                  'confirmations': 10}],
        raw={prev.id().hex(): 'deadbeef'})
    with pytest.raises(ValueError, match='raw tx'):
        ms_create_psbt(seed=WALLET_SEED, passphrase='', backend=backend,
                       dst=dst, amount=50_000, n=3, m=2, keys=cosigners,
                       own_nonce=0, confirmations=6, feekb=1000,
                       fee=1000)


def test_ms_create_psbt_explicit_fee_and_quorum_cashback_dust():
    _keys, _addr, _redeem, script = wallet_fixture_quorum()
    prev = wire_prev_tx(script, b'\x7a' * 32)
    backend = backend_for(prev, script)
    dst = wallet_dst()
    cosigners = [wallet_pubkey(1), wallet_pubkey(2)]

    # Explicit fee: the loop is skipped, fee lands exactly where put.
    outcome = ms_create_psbt(seed=WALLET_SEED, passphrase='',
                             backend=backend, dst=dst, amount=50_000,
                             n=3, m=2, keys=cosigners, own_nonce=0,
                             confirmations=6, feekb=1000, fee=1000)
    assert outcome.fee == 1000
    assert outcome.amount == 50_000
    assert outcome.cashback == 9_000
    assert outcome.fee + outcome.amount + outcome.cashback == 60_000

    # amount 59_600 with fee 350 -> cashback 50 sat: below the P2SH
    # dust threshold (540) — the shared funds stay under quorum
    # control even when the change is dust.
    outcome = ms_create_psbt(seed=WALLET_SEED, passphrase='',
                             backend=backend, dst=dst, amount=59_600,
                             n=3, m=2, keys=cosigners, own_nonce=0,
                             confirmations=6, feekb=1000, fee=350)
    assert outcome.cashback == 50
    assert is_dust(amount=outcome.cashback, script=script)


# --- 6. Parity KAT (generated from the Rust oracle) ----------------------
#
# Production recipe (pinned at commit 3b48499 of the yubtc Rust repo,
# the Phase 15 stage-1 multisig oracle):
#
#     git -C <rust-worktree> archive 3b48499 | tar -x -C <snapshot>
#     # add <snapshot>/core/examples/msgen.rs (the row generator:
#     # the ms fixtures of core/src/psbt.rs -- SEED "phase15multisig",
#     # 2-of-3 over nonces 0..2, prev [0x22;32] paying 60_000 sat to
#     # the P2SH quorum, dst native at nonce 9 for 50_000 -- run
#     # through create -> sign_input(0) -> sign_input(1) -> combine ->
#     # finalize -> extract)
#     cargo run --release --example msgen -p yubtc-core
#
# Each row: `unsigned`/`signed_a`/`signed_ab`/`combined`/`finalized`
# are the stage base64 strings, `wire_hex` the extracted wire
# transaction, `redeem_hex`/`address`/`script_pubkey_hex` the quorum
# constants, `txid` the display txid. ECDSA parity is direct (both
# sides sign the sighash digest since 3f97d66) -- no transformer on
# the Python side.
MS_ROWS = {
    'redeem_hex':
        '522102d60e226aa3c86e7c3dfd5a58dc34bee7c7c8a3df2edca45de9b14ae41e8b444f21039a'
        '3db5a703bbe77f6483655ebfa96075ac7431a64519264334f0ca0f33ce7d6e2103efe4e84e93'
        'eb053414fc402ab62804cea3806a4a105e30959e536a38e613efd553ae',
    'address':
        '3M8uWojbqRXAmPA3UChxa2xpaGj293Nm9q',
    'script_pubkey_hex':
        'a914d54fdaceae101ce76c90ed58e07e53eea8e7af2387',
    'unsigned':
        'cHNidP8BAFICAAAAAbaN19pnpCWQoUsOStMWnjuA0RUQnI3ngksiLldR4piTAAAAAAD+////AVDD'
        'AAAAAAAAFgAUBlq/YtRuBu2G9jT2MAT04yPUQAUAAAAAAAEAUwIAAAABIiIiIiIiIiIiIiIiIiIi'
        'IiIiIiIiIiIiIiIiIiIiIiIAAAAAAP////8BYOoAAAAAAAAXqRTVT9rOrhAc52yQ7VjgflPuqOev'
        'I4cAAAAAAQRpUiEC1g4iaqPIbnw9/VpY3DS+58fIo98u3KRd6bFK5B6LRE8hA5o9tacDu+d/ZINl'
        'Xr+pYHWsdDGmRRkmQzTwyg8zzn1uIQPv5OhOk+sFNBT8QCq2KATOo4BqShBeMJWeU2o45hPv1VOu'
        'AAA=',
    'signed_a':
        'cHNidP8BAFICAAAAAbaN19pnpCWQoUsOStMWnjuA0RUQnI3ngksiLldR4piTAAAAAAD+////AVDD'
        'AAAAAAAAFgAUBlq/YtRuBu2G9jT2MAT04yPUQAUAAAAAAAEAUwIAAAABIiIiIiIiIiIiIiIiIiIi'
        'IiIiIiIiIiIiIiIiIiIiIiIAAAAAAP////8BYOoAAAAAAAAXqRTVT9rOrhAc52yQ7VjgflPuqOev'
        'I4cAAAAAIgIC1g4iaqPIbnw9/VpY3DS+58fIo98u3KRd6bFK5B6LRE9IMEUCIQCMaIDOhc86kWxO'
        'vzFIMxrhu7wQFSP4EcqiIJ97QKKyEwIgCGte67h6dL1MMO0wxGD6AIxEK5LVfzac1UBN6P7f+6EB'
        'AQRpUiEC1g4iaqPIbnw9/VpY3DS+58fIo98u3KRd6bFK5B6LRE8hA5o9tacDu+d/ZINlXr+pYHWs'
        'dDGmRRkmQzTwyg8zzn1uIQPv5OhOk+sFNBT8QCq2KATOo4BqShBeMJWeU2o45hPv1VOuAAA=',
    'signed_ab':
        'cHNidP8BAFICAAAAAbaN19pnpCWQoUsOStMWnjuA0RUQnI3ngksiLldR4piTAAAAAAD+////AVDD'
        'AAAAAAAAFgAUBlq/YtRuBu2G9jT2MAT04yPUQAUAAAAAAAEAUwIAAAABIiIiIiIiIiIiIiIiIiIi'
        'IiIiIiIiIiIiIiIiIiIiIiIAAAAAAP////8BYOoAAAAAAAAXqRTVT9rOrhAc52yQ7VjgflPuqOev'
        'I4cAAAAAIgIC1g4iaqPIbnw9/VpY3DS+58fIo98u3KRd6bFK5B6LRE9IMEUCIQCMaIDOhc86kWxO'
        'vzFIMxrhu7wQFSP4EcqiIJ97QKKyEwIgCGte67h6dL1MMO0wxGD6AIxEK5LVfzac1UBN6P7f+6EB'
        'IgID7+ToTpPrBTQU/EAqtigEzqOAakoQXjCVnlNqOOYT79VHMEQCIFafxREaBL9jJJJOZT+DnbF/'
        'N8mhIXunh4Agg5IaBSv7AiAddKOvumrtxkL5oDlWCy/6p0FNORRG4tgR3aznaVN41AEBBGlSIQLW'
        'DiJqo8hufD39WljcNL7nx8ij3y7cpF3psUrkHotETyEDmj21pwO7539kg2Vev6lgdax0MaZFGSZD'
        'NPDKDzPOfW4hA+/k6E6T6wU0FPxAKrYoBM6jgGpKEF4wlZ5TajjmE+/VU64AAA==',
    'combined':
        'cHNidP8BAFICAAAAAbaN19pnpCWQoUsOStMWnjuA0RUQnI3ngksiLldR4piTAAAAAAD+////AVDD'
        'AAAAAAAAFgAUBlq/YtRuBu2G9jT2MAT04yPUQAUAAAAAAAEAUwIAAAABIiIiIiIiIiIiIiIiIiIi'
        'IiIiIiIiIiIiIiIiIiIiIiIAAAAAAP////8BYOoAAAAAAAAXqRTVT9rOrhAc52yQ7VjgflPuqOev'
        'I4cAAAAAIgIC1g4iaqPIbnw9/VpY3DS+58fIo98u3KRd6bFK5B6LRE9IMEUCIQCMaIDOhc86kWxO'
        'vzFIMxrhu7wQFSP4EcqiIJ97QKKyEwIgCGte67h6dL1MMO0wxGD6AIxEK5LVfzac1UBN6P7f+6EB'
        'IgID7+ToTpPrBTQU/EAqtigEzqOAakoQXjCVnlNqOOYT79VHMEQCIFafxREaBL9jJJJOZT+DnbF/'
        'N8mhIXunh4Agg5IaBSv7AiAddKOvumrtxkL5oDlWCy/6p0FNORRG4tgR3aznaVN41AEBBGlSIQLW'
        'DiJqo8hufD39WljcNL7nx8ij3y7cpF3psUrkHotETyEDmj21pwO7539kg2Vev6lgdax0MaZFGSZD'
        'NPDKDzPOfW4hA+/k6E6T6wU0FPxAKrYoBM6jgGpKEF4wlZ5TajjmE+/VU64AAA==',
    'finalized':
        'cHNidP8BAFICAAAAAbaN19pnpCWQoUsOStMWnjuA0RUQnI3ngksiLldR4piTAAAAAAD+////AVDD'
        'AAAAAAAAFgAUBlq/YtRuBu2G9jT2MAT04yPUQAUAAAAAAAEAUwIAAAABIiIiIiIiIiIiIiIiIiIi'
        'IiIiIiIiIiIiIiIiIiIiIiIAAAAAAP////8BYOoAAAAAAAAXqRTVT9rOrhAc52yQ7VjgflPuqOev'
        'I4cAAAAAAQf9/QAASDBFAiEAjGiAzoXPOpFsTr8xSDMa4bu8EBUj+BHKoiCfe0CishMCIAhrXuu4'
        'enS9TDDtMMRg+gCMRCuS1X82nNVATej+3/uhAUcwRAIgVp/FERoEv2Mkkk5lP4OdsX83yaEhe6eH'
        'gCCDkhoFK/sCIB10o6+6au3GQvmgOVYLL/qnQU05FEbi2BHdrOdpU3jUAUxpUiEC1g4iaqPIbnw9'
        '/VpY3DS+58fIo98u3KRd6bFK5B6LRE8hA5o9tacDu+d/ZINlXr+pYHWsdDGmRRkmQzTwyg8zzn1u'
        'IQPv5OhOk+sFNBT8QCq2KATOo4BqShBeMJWeU2o45hPv1VOuAAA=',
    'wire_hex':
        '0200000001b68dd7da67a42590a14b0e4ad3169e3b80d115109c8de7824b222e5751e2989300'
        '000000fdfd00004830450221008c6880ce85cf3a916c4ebf3148331ae1bbbc101523f811caa2'
        '209f7b40a2b2130220086b5eebb87a74bd4c30ed30c460fa008c442b92d57f369cd5404de8fe'
        'dffba1014730440220569fc5111a04bf6324924e653f839db17f37c9a1217ba787802083921a'
        '052bfb02201d74a3afba6aedc642f9a039560b2ffaa7414d391446e2d811ddace7695378d401'
        '4c69522102d60e226aa3c86e7c3dfd5a58dc34bee7c7c8a3df2edca45de9b14ae41e8b444f21'
        '039a3db5a703bbe77f6483655ebfa96075ac7431a64519264334f0ca0f33ce7d6e2103efe4e8'
        '4e93eb053414fc402ab62804cea3806a4a105e30959e536a38e613efd553aefeffffff0150c3'
        '000000000000160014065abf62d46e06ed86f634f63004f4e323d4400500000000',
    'txid':
        '4d338be0c9c85d294077d11fef90901e6890e3db4ed85e2b0cfe98402d6cb319',
}

# First-bytes table: every PSBT stage begins with the BIP-174 magic +
# version-0 header + the `UNSIGNED_TX` valuelen (0x52 = the 82-byte
# stripped fixture tx) -- the D-002 CompactSize marker lives deeper,
# in the extracted wire (`fd fd 00` at byte 41, pinned in
# test_wire_kat_carries_compact_size_scriptsig_length).
FIRST_BYTES = {
    'unsigned': '70736274ff010052',
    'signed_a': '70736274ff010052',
    'signed_ab': '70736274ff010052',
    'combined': '70736274ff010052',
    'finalized': '70736274ff010052',
    'wire_hex': '0200000001b68dd7',
}


def test_rust_parity_rows():
    # Replay the fixture through the whole pipeline and pin every
    # stage byte-for-byte against the Rust oracle's rows.
    psbt = ms_fixture_psbt()
    assert to_base64(psbt=psbt) == MS_ROWS['unsigned']
    assert sign_psbt_input(psbt=psbt, index=0, privkey=ms_key(0))
    assert to_base64(psbt=psbt) == MS_ROWS['signed_a']
    psbt_b = ms_fixture_psbt()
    assert sign_psbt_input(psbt=psbt_b, index=0, privkey=ms_key(1))
    combined = combine_psbt(psbt=psbt, other=psbt_b)
    assert to_base64(psbt=combined) == MS_ROWS['combined']
    assert to_base64(psbt=combined) == MS_ROWS['signed_ab']
    finalize_psbt(psbt=combined)
    assert to_base64(psbt=combined) == MS_ROWS['finalized']
    assert serialize_psbt(psbt=combined).hex() \
        == base64.b64decode(MS_ROWS['finalized']).hex()
    tx = extract_transaction(psbt=combined)
    assert tx.serialize_wire().hex() == MS_ROWS['wire_hex']
    # Structural pins.
    assert tx.id().hex() == MS_ROWS['txid']
    assert len(tx.vin[0].script) == 253


def test_ms_rows_quorum_constants():
    # The quorum constants embedded in the KAT come from the same
    # fixture the Python mirror derives from SEED.
    assert ms_redeem().hex() == MS_ROWS['redeem_hex']
    assert redeem2p2sh_addr(redeem=ms_redeem()) == MS_ROWS['address']
    assert ms_p2sh_spk().hex() == MS_ROWS['script_pubkey_hex']
    assert sorted([ms_pub(0), ms_pub(1), ms_pub(2)]) == ms_redeem_keys()


def test_ms_rows_first_bytes_table():
    # The pinned first-bytes table: identical BIP-174 headers across
    # the stages, and the wire's version+txid head.
    for stage, expected in FIRST_BYTES.items():
        blob = MS_ROWS[stage]
        if stage == 'wire_hex':
            head = blob[:len(expected)]
        else:
            head = base64.b64decode(blob)[:8].hex()
        assert head == expected, stage
    # And the live pipeline agrees with the table.
    psbt = ms_fixture_psbt()
    assert base64.b64decode(to_base64(psbt=psbt))[:8].hex() \
        == FIRST_BYTES['unsigned']
