"""Tests for the wallet-layer Phase 13 additions.

AddrType selection and path mapping (`TPrivKey.addr_type` /
`address_of`), UTXO validation for the witness forms
(`validate_utxo_script`), witness spending in `_make_vin` /
`make_transaction`, the vsize fee loop, dust thresholds, and the
vsize-aware announce line.
"""
import pytest

import yubtc.net
from yubtc.fwd import (DEFAULT_ADDR_TYPE, DUST_THRESHOLD_P2PKH,
                       DUST_THRESHOLD_P2SH, DUST_THRESHOLD_P2TR,
                       DUST_THRESHOLD_P2WPKH, AddrType, ADDR_TYPES)

# The 'qwe' nonce-0 legacy key derives these pinned values (the legacy
# ones are the historic v0.1 vectors).
SEED = 'qwe'
LEGACY_ADDRESS = '1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
PRIVWIF = 'Kx2X5mom9zTGkQq38v8swx3z5ApAuRnwq4wfyF52Y55v6Ke5dRq5'


def _mk_tp(seed=SEED, nonce=0, passphrase='', addr_type=None):
    from yubtc.wallet import TPrivKey
    if addr_type is None:
        return TPrivKey(seed=seed, nonce=nonce, passphrase=passphrase,
                        backend=object())
    return TPrivKey(seed=seed, nonce=nonce, passphrase=passphrase,
                    backend=object(), addr_type=addr_type)


def _stub_unused(monkeypatch, unspent_by_address=None):
    """Stub the two net entry points: every address is unused unless it
    has UTXOs in `unspent_by_address`."""
    unspent_by_address = unspent_by_address or {}

    def fake_info(backend, address):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        return {'total_received': 1 if address in unspent_by_address else 0,
                'final_balance': 0, 'n_tx': 0}

    def fake_unspent(backend, address, **kwargs):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        return unspent_by_address.get(address, [])
    monkeypatch.setattr(yubtc.net, 'get_address_info', fake_info)
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent)


def _mk_wallet(monkeypatch, addr_type=None):
    """An offline Wallet at the gap (no UTXOs anywhere)."""
    _stub_unused(monkeypatch)
    from yubtc.wallet import Wallet
    if addr_type is None:
        return Wallet(seed=SEED, nonce=0, new_addresses=1, passphrase='',
                      backend=object())
    return Wallet(seed=SEED, nonce=0, new_addresses=1, passphrase='',
                  backend=object(), addr_type=addr_type)


def _unspent_entry(spk_hex, amount=10_000, n=0):
    return {'tx': 'ab' * 32, 'out_n': n, 'amount': amount,
            'script': spk_hex, 'confirmations': 6}


def _tp_with_pubkey():
    from yubtc.crypto import privkey2pubkey
    tp = _mk_tp()
    return tp, privkey2pubkey(privkey=tp.privkey)


# ---------------------------------------------------------------------------
# fwd: AddrType / dust constants (spec surface pins)
# ---------------------------------------------------------------------------

def test_addr_type_values_and_default():
    assert AddrType.LEGACY == 'legacy'
    assert AddrType.NATIVE == 'native'
    assert AddrType.TAPROOT == 'taproot'
    assert ADDR_TYPES == ('legacy', 'native', 'taproot')
    # Spec ОВ-1: the default address type after Phase 13 is Native.
    assert DEFAULT_ADDR_TYPE == AddrType.NATIVE


def test_dust_thresholds_are_pinned():
    # Bitcoin Core GetDustThreshold, dustRelayFee = 3 sat/kvB.
    assert DUST_THRESHOLD_P2PKH == 546
    assert DUST_THRESHOLD_P2SH == 540
    assert DUST_THRESHOLD_P2WPKH == 294
    assert DUST_THRESHOLD_P2TR == 330


# ---------------------------------------------------------------------------
# is_dust: per-form thresholds
# ---------------------------------------------------------------------------

def test_is_dust_thresholds_per_form():
    from yubtc.misc import is_dust
    p2pkh = bytes([0x76, 0xa9, 0x14]) + bytes(20) + bytes([0x88, 0xac])
    p2sh = bytes([0xa9, 0x14]) + bytes(20) + bytes([0x87])
    p2wpkh = bytes([0x00, 0x14]) + bytes(20)
    p2tr = bytes([0x51, 0x20]) + bytes(32)
    assert is_dust(amount=545, script=p2pkh)
    assert not is_dust(amount=546, script=p2pkh)
    assert is_dust(amount=539, script=p2sh)
    assert not is_dust(amount=540, script=p2sh)
    assert is_dust(amount=293, script=p2wpkh)
    assert not is_dust(amount=294, script=p2wpkh)
    assert is_dust(amount=329, script=p2tr)
    assert not is_dust(amount=330, script=p2tr)
    # Unknown shapes are never flagged (UTXO validation rejects them).
    assert not is_dust(amount=1, script=b'\xac')
    assert not is_dust(amount=1, script=bytes(24))


# ---------------------------------------------------------------------------
# validate_utxo_script: the four spendable forms
# ---------------------------------------------------------------------------

def test_validate_utxo_script_accepts_canonical_forms():
    from yubtc.wallet import validate_utxo_script
    assert validate_utxo_script(
        script=bytes([0x76, 0xa9, 0x14]) + bytes(20) + bytes([0x88, 0xac])) == 'p2pkh'
    assert validate_utxo_script(
        script=bytes([0xa9, 0x14]) + bytes(20) + bytes([0x87])) == 'p2sh'
    assert validate_utxo_script(script=bytes([0x00, 0x14]) + bytes(20)) == 'p2wpkh'
    assert validate_utxo_script(script=bytes([0x51, 0x20]) + bytes(32)) == 'p2tr'


def test_validate_utxo_script_rejects_malformed_shapes():
    from yubtc.wallet import validate_utxo_script
    # P2PKH length with a wrong opcode.
    with pytest.raises(ValueError, match='invalid script'):
        validate_utxo_script(script=bytes(25))
    # P2SH length with wrong opcodes.
    with pytest.raises(ValueError, match='unsupported utxo script'):
        validate_utxo_script(script=bytes(23))
    # P2WPKH length with a wrong version/push byte.
    with pytest.raises(ValueError, match='expected P2WPKH layout'):
        validate_utxo_script(script=bytes([0x01, 0x14]) + bytes(20))
    with pytest.raises(ValueError, match='expected P2WPKH layout'):
        validate_utxo_script(script=bytes([0x00, 0x15]) + bytes(20))
    # P2TR length with a wrong version/push byte.
    with pytest.raises(ValueError, match='expected P2TR layout'):
        validate_utxo_script(script=bytes([0x00, 0x20]) + bytes(32))
    with pytest.raises(ValueError, match='expected P2TR layout'):
        validate_utxo_script(script=bytes([0x51, 0x21]) + bytes(32))
    # Any other length.
    with pytest.raises(ValueError, match='unsupported utxo script'):
        validate_utxo_script(script=bytes(24))
    with pytest.raises(ValueError, match='unsupported utxo script'):
        validate_utxo_script(script=b'')


# ---------------------------------------------------------------------------
# TPrivKey: addr_type selection and address_of
# ---------------------------------------------------------------------------

def test_tp_privkey_default_is_legacy_and_bit_compatible():
    tp = _mk_tp()
    assert tp._addr_type == AddrType.LEGACY
    assert tp.get_p2pkh_address().decode('ascii') == LEGACY_ADDRESS
    assert tp.get_privwif() == PRIVWIF.encode('ascii')
    # address_of(legacy) matches the historic address, returned as str.
    assert tp.address_of(addr_type=AddrType.LEGACY) == LEGACY_ADDRESS


def test_address_of_segwit_and_taproot_forms():
    from yubtc.crypto import privkey2pubkey, pubkey2segwit_addr, pubkey2taproot_addr
    tp = _mk_tp()
    pubkey = privkey2pubkey(privkey=tp.privkey)
    assert tp.address_of(addr_type=AddrType.NATIVE) == \
        pubkey2segwit_addr(pubkey=pubkey)
    assert tp.address_of(addr_type=AddrType.TAPROOT) == \
        pubkey2taproot_addr(pubkey=pubkey)
    assert tp.address_of(addr_type=AddrType.NATIVE).startswith('bc1q')
    assert tp.address_of(addr_type=AddrType.TAPROOT).startswith('bc1p')


def test_address_of_defaults_to_derivation_type():
    tp = _mk_tp(addr_type=AddrType.TAPROOT)
    assert tp.address_of() == tp.address_of(addr_type=AddrType.TAPROOT)
    tp = _mk_tp(addr_type=AddrType.NATIVE)
    assert tp.address_of() == tp.address_of(addr_type=AddrType.NATIVE)


def test_address_of_rejects_unknown_type():
    tp = _mk_tp()
    with pytest.raises(ValueError, match='unknown addr type'):
        tp.address_of(addr_type='bech32')


def test_tp_privkey_rejects_unknown_addr_type():
    with pytest.raises(ValueError, match='unknown addr type'):
        _mk_tp(addr_type='p2sh')


def test_tp_privkey_variant_a_same_key_different_encoding():
    # Variant A (ОВ-2) for the non-BIP-32 yubtc KDF: the WIF is
    # identical across address types; only the encoding differs.
    legacy = _mk_tp(addr_type=AddrType.LEGACY)
    native = _mk_tp(addr_type=AddrType.NATIVE)
    taproot = _mk_tp(addr_type=AddrType.TAPROOT)
    assert legacy.get_privwif() == native.get_privwif() == taproot.get_privwif()
    assert native.address_of() != legacy.address_of()
    assert taproot.address_of() != legacy.address_of()


def test_tp_privkey_pbkdf2_walks_purpose_paths():
    # For the pbkdf2 KDF the address type selects the BIP-32 purpose:
    # a native-typed TPrivKey derives the m/84' leaf (the key the
    # external BIP-84 wallets reproduce), not the m/44' one.
    from yubtc.crypto import seed2privkey
    tp_native = _mk_tp(passphrase='x', addr_type=AddrType.NATIVE)
    assert tp_native.privkey == seed2privkey(seed=SEED, nonce=0,
                                             passphrase='x',
                                             addr_type=AddrType.NATIVE)
    assert tp_native.privkey != seed2privkey(seed=SEED, nonce=0,
                                             passphrase='x',
                                             addr_type=AddrType.LEGACY)
    # The cashback/address surface follows the derivation type.
    assert tp_native.address_of() == tp_native.address_of(addr_type='native')


def test_wallet_threads_addr_type(monkeypatch):
    wallet = _mk_wallet(monkeypatch, addr_type=AddrType.TAPROOT)
    assert wallet._addr_type == AddrType.TAPROOT
    assert all(pk._addr_type == AddrType.TAPROOT for pk in wallet.privkeys)
    # Omitted stays legacy (the v0.1 scan-compatible default).
    wallet = _mk_wallet(monkeypatch)
    assert wallet._addr_type == AddrType.LEGACY


def test_wallet_rejects_unknown_addr_type(monkeypatch):
    _stub_unused(monkeypatch)
    from yubtc.wallet import Wallet
    with pytest.raises(ValueError, match='unknown addr type'):
        Wallet(seed=SEED, nonce=0, new_addresses=1, passphrase='',
               backend=object(), addr_type='segwit')


# ---------------------------------------------------------------------------
# _make_vin: witness UTXOs and the spend context
# ---------------------------------------------------------------------------

def test_make_vin_accepts_witness_utxos(monkeypatch):
    from yubtc.crypto import taproot_output_key
    from yubtc.hash import hash160
    tp, pubkey = _tp_with_pubkey()
    pubhash = hash160(pubkey)
    output_key = taproot_output_key(internal_xonly=pubkey[1:33])
    spk_p2wpkh = bytes([0x00, 0x14]) + pubhash
    spk_p2tr = bytes([0x51, 0x20]) + output_key
    unspent = [_unspent_entry(spk_p2wpkh.hex(), amount=7_000, n=0),
               _unspent_entry(spk_p2tr.hex(), amount=9_000, n=1)]
    vin, in_amount, signers, spend = _mk_wallet(monkeypatch)._make_vin(
        sources=[(tp, unspent)])
    assert in_amount == 16_000
    assert [vin[0].script, vin[1].script] == [spk_p2wpkh, spk_p2tr]
    assert all(v.witness == () for v in vin)
    assert [(s.amount, s.script_pubkey) for s in spend] == \
        [(7_000, spk_p2wpkh), (9_000, spk_p2tr)]
    assert signers == [(tp.privkey, pubkey)] * 2


def test_make_vin_rejects_foreign_and_unspendable_scripts(monkeypatch):
    from yubtc.hash import hash160
    tp, pubkey = _tp_with_pubkey()
    wallet = _mk_wallet(monkeypatch)
    foreign_p2wpkh = bytes([0x00, 0x14]) + b'\x11' * 20
    with pytest.raises(ValueError, match='unknown pubkey required'):
        wallet._make_vin(sources=[(tp, [_unspent_entry(foreign_p2wpkh.hex())])])
    foreign_p2tr = bytes([0x51, 0x20]) + b'\x22' * 32
    with pytest.raises(ValueError, match='unknown pubkey required'):
        wallet._make_vin(sources=[(tp, [_unspent_entry(foreign_p2tr.hex())])])
    p2sh = bytes([0xa9, 0x14]) + hash160(pubkey) + bytes([0x87])
    with pytest.raises(ValueError, match='p2sh utxo cannot be spent'):
        wallet._make_vin(sources=[(tp, [_unspent_entry(p2sh.hex())])])
    with pytest.raises(ValueError, match='unsupported utxo script'):
        wallet._make_vin(sources=[(tp, [_unspent_entry('aa' * 24)])])


# ---------------------------------------------------------------------------
# make_transaction: witness signing, vsize fee loop, announce
# ---------------------------------------------------------------------------

def _send_one_utxo(monkeypatch, spk, amount=50_000, fee=1_000):
    """Run make_transaction over a single crafted UTXO (drain mode)."""
    from yubtc.crypto import privkey2pubkey, pubkey2addr
    tp = _mk_tp()
    pubkey = privkey2pubkey(privkey=tp.privkey)
    dst = pubkey2addr(pubkey=pubkey).decode('ascii')
    wallet = _mk_wallet(monkeypatch)
    result = wallet.make_transaction(
        dst=dst, amount=None, feekb=1000, fee=fee, confirmations=6,
        scan=False, sources=[(tp, [_unspent_entry(spk.hex(), amount=amount)])],
        cashback_addr=dst, on_address=None)
    return result, tp, pubkey, dst


def test_make_transaction_spends_p2wpkh_utxo_with_witness(monkeypatch):
    from yubtc.hash import hash160
    from yubtc.transaction import CIn, CTransaction
    tp, pubkey = _tp_with_pubkey()
    spk_p2wpkh = bytes([0x00, 0x14]) + hash160(pubkey)
    result, tp, pubkey, _dst = _send_one_utxo(monkeypatch, spk_p2wpkh)
    tx = result.tx
    # The P2WPKH input is witness-signed: empty scriptSig, two items.
    assert tx.vin[0].script == b''
    assert len(tx.vin[0].witness) == 2
    assert tx.vin[0].witness[1] == pubkey
    assert tx.vin[0].witness[0][-1] == 0x01  # SIGHASH_ALL
    # The wire carries the witness and follows BIP-141 accounting.
    assert tx.has_witness()
    assert len(tx.serialize_wire()) > len(tx.serialize_stripped())
    assert tx.weight() == len(tx.serialize_stripped()) * 3 + len(tx.serialize_wire())
    assert tx.vsize() == -(-tx.weight() // 4)
    # Discount pin: the same UTXO spent via the legacy path costs
    # strictly more vsize (~148 bytes of scriptSig vs the discounted
    # witness).
    spk_p2pkh = bytes([0x76, 0xa9, 0x14]) + hash160(pubkey) + bytes([0x88, 0xac])
    legacy_tx = CTransaction(
        vin=[CIn(txhash=tx.vin[0].txhash, n=tx.vin[0].n, script=spk_p2pkh,
                 sequence=tx.vin[0].sequence)],
        vout=tx.vout, locktime=tx.locktime)
    legacy_signed = legacy_tx.sign(signers=[(tp.privkey, pubkey)])
    assert legacy_signed.vsize() == len(legacy_signed.serialize())
    assert tx.vsize() < legacy_signed.vsize()


def test_make_transaction_fee_loop_uses_vsize_and_legacy_matches_bytes(monkeypatch):
    from yubtc.hash import hash160
    _tp, pubkey = _tp_with_pubkey()
    p2pkh_spk = bytes([0x76, 0xa9, 0x14]) + hash160(pubkey) + bytes([0x88, 0xac])
    # fee=0 drives the fee loop (its size unit is the vsize now).
    result, _tp, _pubkey, _dst = _send_one_utxo(monkeypatch, p2pkh_spk, fee=0)
    # Legacy tx: vsize == wire bytes == stripped bytes (v0.1 parity).
    assert result.tx.vsize() == len(result.tx.serialize())
    assert not result.tx.has_witness()


def test_announce_tx_prints_bytes_and_vsize(monkeypatch, capsys):
    from yubtc.hash import hash160
    from yubtc.wallet import _announce_tx
    _tp, pubkey = _tp_with_pubkey()
    spk_p2wpkh = bytes([0x00, 0x14]) + hash160(pubkey)
    result, _tp, _pubkey, dst = _send_one_utxo(monkeypatch, spk_p2wpkh)
    _announce_tx(backend=object(), result=result, dst=dst,
                 broadcast=False, yes=True)
    out = capsys.readouterr().out
    assert 'txsize={}'.format(len(result.tx.serialize_wire())) in out
    assert 'vsize={}'.format(result.tx.vsize()) in out
