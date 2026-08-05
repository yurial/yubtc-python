"""Tests for transaction.py: the Bitcoin transaction model.

These are the structs and serialization that get sent to the network.
A silent change here would let the wallet produce transactions the
network rejects, so the bytes are pinned via known-answer tests where
hand-computation is feasible.

`toVarInt` (LEB128-style) is a different encoding from `misc.varint`
(CompactSize). See `tests/test_misc.py` for the other one.
"""
import pytest

from yubtc.script import OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG


# ---------------------------------------------------------------------------
# script2pkh: extract the 20-byte hash from a P2PKH script.
# ---------------------------------------------------------------------------

def _p2pkh_script(hash20: bytes) -> bytes:
    return bytes([OP_DUP, OP_HASH160, 20]) + hash20 + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


def test_script2pkh_extracts_hash():
    from yubtc.transaction import script2pkh
    payload = b'\xaa\x55\xaa\x55' + b'\x00' * 16
    script = _p2pkh_script(payload)
    assert script2pkh(script) == payload


def test_script2pkh_rejects_wrong_length():
    from yubtc.transaction import script2pkh
    # 24 bytes, not 25
    with pytest.raises(Exception):
        script2pkh(b'\x00' * 24)


def test_script2pkh_rejects_wrong_opcodes():
    from yubtc.transaction import script2pkh
    hash20 = b'\x00' * 20
    # Each of these swaps one byte of the canonical P2PKH script.
    for bad in (
        bytes([0x00]) + _p2pkh_script(hash20)[1:],                   # OP_DUP -> 0x00
        _p2pkh_script(hash20)[:1] + bytes([0x00]) + _p2pkh_script(hash20)[2:],  # OP_HASH160 -> 0x00
        _p2pkh_script(hash20)[:2] + bytes([21]) + _p2pkh_script(hash20)[3:],    # push 21 instead of 20
        _p2pkh_script(hash20)[:-2] + bytes([0x00]) + _p2pkh_script(hash20)[-1:],  # OP_EQUALVERIFY -> 0x00
        _p2pkh_script(hash20)[:-1] + bytes([0x00]),                  # OP_CHECKSIG -> 0x00
    ):
        with pytest.raises(Exception):
            script2pkh(bad)


# ---------------------------------------------------------------------------
# toVarInt: LEB128-style 7-bit groups with continuation bit.
#
# Note: this is *not* the same as `misc.varint` (CompactSize).
# - 0           -> 1 byte, 0x00
# - 0x7f        -> 1 byte, 0x7f
# - 0x80        -> 2 bytes, 0x80 0x01 (continuation bit + 0)
# - 0x4000      -> 3 bytes, 0x80 0x80 0x01
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    (0, b'\x00'),
    (1, b'\x01'),
    (0x7f, b'\x7f'),
    (0x80, b'\x80\x01'),
    (0xff, b'\xff\x01'),
    (0x100, b'\x80\x02'),
    (0x3fff, b'\xff\x7f'),
    (0x4000, b'\x80\x80\x01'),
    (0xffff, b'\xff\xff\x03'),
    (0xffffff, b'\xff\xff\xff\x07'),
])
def test_toVarInt(value, expected):
    from yubtc.transaction import toVarInt
    assert toVarInt(value) == expected


def test_toVarInt_rejects_negative():
    """Without a sign check, `value >> 7` arithmetic-shifts a negative
    value forever -- the loop never terminates. The sign check at the
    top of `toVarInt` converts that into a clean error.
    """
    from yubtc.transaction import toVarInt
    with pytest.raises(Exception):
        toVarInt(-1)
    with pytest.raises(Exception):
        toVarInt(-100)


# ---------------------------------------------------------------------------
# CIn: a transaction input.
# ---------------------------------------------------------------------------

TXHASH = b'\xab' * 32


def test_cin_valid_construction():
    from yubtc.transaction import CIn
    inp = CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff)
    assert inp.txhash == TXHASH
    assert inp.n == 0
    assert inp.script == b''
    assert inp.sequence == 0xffffffff  # explicit final


def test_cin_txhash_must_be_32_bytes():
    from yubtc.transaction import CIn
    with pytest.raises(Exception):
        CIn(txhash=b'\x00' * 31, n=0, script=b'', sequence=0xffffffff)
    with pytest.raises(Exception):
        CIn(txhash=b'\x00' * 33, n=0, script=b'', sequence=0xffffffff)


def test_cin_n_bounds():
    from yubtc.transaction import CIn
    # n=0 is allowed (first output of the referenced tx).
    CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff)
    # n at the upper bound
    CIn(txhash=TXHASH, n=0xffffffff, script=b'', sequence=0xffffffff)
    with pytest.raises(Exception):
        CIn(txhash=TXHASH, n=-1, script=b'', sequence=0xffffffff)
    with pytest.raises(Exception):
        CIn(txhash=TXHASH, n=0x100000000, script=b'', sequence=0xffffffff)


def test_cin_sequence_bounds():
    from yubtc.transaction import CIn
    # sequence=0 is allowed (BIP-125 replaceable).
    CIn(txhash=TXHASH, n=0, script=b'', sequence=0)
    CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff)
    with pytest.raises(Exception):
        CIn(txhash=TXHASH, n=0, script=b'', sequence=-1)
    with pytest.raises(Exception):
        CIn(txhash=TXHASH, n=0, script=b'', sequence=0x100000000)


def test_cin_raises_when_sequence_missing():
    """CIn's `sequence` is required -- callers must pass it explicitly."""
    from yubtc.transaction import CIn
    with pytest.raises(Exception, match='sequence not set'):
        CIn(txhash=TXHASH, n=0, script=b'')
    with pytest.raises(Exception, match='sequence not set'):
        CIn(txhash=TXHASH, n=0, script=b'', sequence=None)


def test_cin_raises_when_txhash_or_n_missing():
    """txhash and n are also required -- callers must pass them explicitly."""
    from yubtc.transaction import CIn
    with pytest.raises(Exception, match='txhash not set'):
        CIn(n=0, script=b'', sequence=0xffffffff)
    with pytest.raises(Exception, match='n not set'):
        CIn(txhash=TXHASH, script=b'', sequence=0xffffffff)


def test_cout_raises_when_amount_missing():
    """COut's `amount` is required -- callers must pass it explicitly."""
    from yubtc.transaction import COut
    with pytest.raises(Exception, match='amount not set'):
        COut(script=b'')
    with pytest.raises(Exception, match='amount not set'):
        COut(amount=None, script=b'')


def test_ctransaction_raises_when_vin_or_vout_missing():
    """CTransaction requires both `vin` and `vout`."""
    from yubtc.transaction import COut, CTransaction
    base = dict(vin=[], vout=[COut(amount=0, script=b'')], locktime=0)
    with pytest.raises(Exception, match='vin not set'):
        CTransaction(**{**base, 'vin': None})
    with pytest.raises(Exception, match='vout not set'):
        CTransaction(**{**base, 'vout': None})


def test_sign_raises_when_privkey_or_pubwif_missing():
    """sign requires `privkey` and `pubwif`."""
    from yubtc.transaction import CTransaction, COut
    tx = CTransaction(vin=[], vout=[COut(amount=0, script=b'\xac')], locktime=0)
    with pytest.raises(Exception, match='privkey not set'):
        tx.sign(pubwif=b'\x02' + b'\x00' * 32)
    with pytest.raises(Exception, match='privkey not set'):
        tx.sign(privkey=None, pubwif=b'\x02' + b'\x00' * 32)
    with pytest.raises(Exception, match='pubwif not set'):
        tx.sign(privkey=b'\x11' * 32)
    with pytest.raises(Exception, match='pubwif not set'):
        tx.sign(privkey=b'\x11' * 32, pubwif=None)


def test_multi_arg_transaction_methods_reject_positional_args():
    """CIn / COut / CTransaction / sign all require kwargs-only calls."""
    from yubtc.transaction import CIn, COut, CTransaction
    # CIn
    with pytest.raises(Exception, match='only kwargs allowed'):
        CIn(TXHASH, 0, b'', sequence=0xffffffff)
    # COut
    with pytest.raises(Exception, match='only kwargs allowed'):
        COut(1000, b'\xac')
    # CTransaction
    with pytest.raises(Exception, match='only kwargs allowed'):
        CTransaction([], [], locktime=0)
    # sign: build a tx first, then attempt positional sign.
    tx = CTransaction(vin=[], vout=[COut(amount=0, script=b'\xac')], locktime=0)
    with pytest.raises(Exception, match='only kwargs allowed'):
        tx.sign(b'\x11' * 32, b'\x02' + b'\x00' * 32)


def test_cin_serialize_known_answer():
    """Pin the exact byte layout of an input.

    32-byte txhash + 4-byte n (LE) + varint(len(script)) + script + 4-byte sequence (LE).
    """
    from yubtc.transaction import CIn
    inp = CIn(txhash=TXHASH, n=0, script=b'\x76\xa9', sequence=0xffffffff)
    assert inp.serialize() == (
        TXHASH
        + b'\x00\x00\x00\x00'    # n=0
        + b'\x02'                   # varint(len(script)) = 2
        + b'\x76\xa9'              # script
        + b'\xff\xff\xff\xff'    # default sequence
    )


def test_cin_serialize_with_sequence_and_empty_script():
    from yubtc.transaction import CIn
    inp = CIn(txhash=TXHASH, n=1, script=b'', sequence=0x12345678)
    assert inp.serialize() == (
        TXHASH
        + b'\x01\x00\x00\x00'
        + b'\x00'                   # varint(0) for empty script
        + b'\x78\x56\x34\x12'    # sequence 0x12345678 LE
    )


# ---------------------------------------------------------------------------
# COut: a transaction output.
# ---------------------------------------------------------------------------

def test_cout_valid_construction():
    from yubtc.transaction import COut
    out = COut(amount=0, script=b'')
    assert out.amount == 0
    # amount=0 is allowed (provably unspendable but syntactically valid).
    assert out.script == b''


def test_cout_amount_bounds():
    from yubtc.transaction import COut
    COut(amount=0xffffffffffffffff, script=b'')
    with pytest.raises(Exception):
        COut(amount=-1, script=b'')
    with pytest.raises(Exception):
        COut(amount=0x10000000000000000, script=b'')


def test_cout_serialize_known_answer():
    """Pin the exact byte layout of an output.

    8-byte amount (LE) + varint(len(script)) + script.
    """
    from yubtc.transaction import COut
    out = COut(amount=100_000, script=b'\x76\xa9')
    assert out.serialize() == (
        b'\xa0\x86\x01\x00\x00\x00\x00\x00'  # 100000 in LE int64
        + b'\x02'
        + b'\x76\xa9'
    )


# ---------------------------------------------------------------------------
# CTransaction: containers + serialization + id + sign.
# ---------------------------------------------------------------------------

def _example_tx():
    """A 1-input, 1-output transaction with a non-trivial locktime."""
    from yubtc.transaction import CIn, COut, CTransaction
    inp = CIn(txhash=TXHASH, n=0, script=b'\x76\xa9', sequence=0xffffffff)
    out = COut(amount=100_000, script=b'\x76\xa9')
    return CTransaction(vin=[inp], vout=[out], locktime=0)


def test_ctransaction_default_version_is_2():
    from yubtc.transaction import CTransaction
    tx = CTransaction(vin=[], vout=[], locktime=0)
    assert tx.version == 2


def test_ctransaction_default_locktime_is_0():
    from yubtc.transaction import CTransaction
    tx = CTransaction(vin=[], vout=[], locktime=0)
    assert tx.locktime == 0


def test_ctransaction_raises_when_locktime_missing():
    """CTransaction's `locktime` is required -- callers must pass it explicitly."""
    from yubtc.transaction import CTransaction
    with pytest.raises(Exception, match='locktime not set'):
        CTransaction(vin=[], vout=[])
    with pytest.raises(Exception, match='locktime not set'):
        CTransaction(vin=[], vout=[], locktime=None)


def test_ctransaction_serialize_known_answer():
    tx = _example_tx()
    assert tx.serialize() == (
        b'\x02\x00\x00\x00'        # version=2
        + b'\x01'                     # varint(1) vin count
        + TXHASH
        + b'\x00\x00\x00\x00'
        + b'\x02\x76\xa9'
        + b'\xff\xff\xff\xff'
        + b'\x01'                     # varint(1) vout count
        + b'\xa0\x86\x01\x00\x00\x00\x00\x00'
        + b'\x02\x76\xa9'
        + b'\x00\x00\x00\x00'      # locktime=0
    )


def test_ctransaction_serialize_with_multiple_inputs_and_outputs():
    from yubtc.transaction import CIn, COut, CTransaction
    in1 = CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff)
    in2 = CIn(txhash=TXHASH, n=1, script=b'\xab', sequence=0xffffffff)
    out1 = COut(amount=1, script=b'')
    out2 = COut(amount=2, script=b'\x76')
    tx = CTransaction(vin=[in1, in2], vout=[out1, out2], locktime=0)
    s = tx.serialize()
    # Each input = 32(txhash) + 4(n) + 1(varint) + len(script) + 4(sequence).
    # Each output = 8(amount) + 1(varint) + len(script).
    # Plus 4(version) + 1(vin count) + 1(vout count) + 4(locktime).
    expected_len = (4 + 1 + 1 + 4
                    + (32 + 4 + 1 + 0 + 4) + (32 + 4 + 1 + 1 + 4)
                    + (8 + 1 + 0) + (8 + 1 + 1))
    assert len(s) == expected_len
    assert s[:4] == b'\x02\x00\x00\x00'
    assert s[-4:] == b'\x00\x00\x00\x00'


def test_ctransaction_id_is_double_sha256_reversed():
    """`id()` is double SHA-256 of the serialized tx, displayed little-endian."""
    from yubtc.hash import sha256
    tx = _example_tx()
    expected = sha256(sha256(tx.serialize()))[::-1]
    assert tx.id() == expected


def test_ctransaction_id_known_answer():
    """Pin the byte-level id for the example tx -- if this shifts, every
    consumer that watches a txid will desynchronise."""
    tx = _example_tx()
    assert tx.id().hex() == '5f74d3c48b7f6f76be52629ea1ea3399131883b5e96e039ba949ff71621fd1b8'


# ---------------------------------------------------------------------------
# CTransaction.sign: each input gets a signature script with the signature
# over the SIGHASH_ALL preimage followed by the pubwif.
# ---------------------------------------------------------------------------

def test_sign_populates_each_input_script():
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = pubkey2pubwif(pubkey=privkey2pubkey(privkey=privkey), compressed=True)
    tx = CTransaction(
        vin=[
            CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff),
            CIn(txhash=TXHASH, n=1, script=b'', sequence=0xffffffff),
        ],
        vout=[COut(amount=1000, script=b'\x76\xa9')],
        locktime=0,
    )
    signed = tx.sign(privkey=privkey, pubwif=pubwif)
    for i, vin in enumerate(signed.vin):
        assert len(vin.script) > 0, f'input {i} has empty script'


def test_sign_script_ends_with_pubwif():
    """The signature script convention is: <signature> <pubkey>.

    The last 33 bytes must be the compressed pubwif (the constant we
    passed in). Anything else means the script is misshapen.
    """
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = pubkey2pubwif(pubkey=privkey2pubkey(privkey=privkey), compressed=True)
    tx = CTransaction(
        vin=[CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=1000, script=b'\x76\xa9')], locktime=0)
    signed = tx.sign(privkey=privkey, pubwif=pubwif)
    assert signed.vin[0].script.endswith(pubwif)


def test_sign_changes_id():
    """Signing alters the tx bytes (signature scripts are added), so the id
    must move. If id() ever returns the same value before and after sign,
    either serialization is broken or the signature scripts are empty.
    """
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = pubkey2pubwif(pubkey=privkey2pubkey(privkey=privkey), compressed=True)
    tx = CTransaction(
        vin=[CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=1000, script=b'\x76\xa9')], locktime=0)
    signed = tx.sign(privkey=privkey, pubwif=pubwif)
    assert signed.id() != tx.id()


def test_sign_does_not_mutate_original():
    """`sign` uses deepcopy internally; the original tx must keep its
    empty signature scripts."""
    from yubtc.transaction import CIn, COut, CTransaction
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    privkey = seed2privkey(seed='qwe', nonce=0)
    pubwif = pubkey2pubwif(pubkey=privkey2pubkey(privkey=privkey), compressed=True)
    tx = CTransaction(
        vin=[CIn(txhash=TXHASH, n=0, script=b'', sequence=0xffffffff)],
        vout=[COut(amount=1000, script=b'\x76\xa9')], locktime=0)
    original_bytes = tx.serialize()
    tx.sign(privkey=privkey, pubwif=pubwif)
    assert tx.serialize() == original_bytes
    assert tx.vin[0].script == b''
