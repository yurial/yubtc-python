"""Phase 13 stage-2 wallet tests: the multi-form scan.

Mirrors the stage-2 Rust tests in `core/src/wallet.rs` (scan_inputs_until
/ Wallet::new with AddrType): one source per contributing (nonce, form),
the gap rule generalised to nonces (a nonce is used when ANY of its
forms ever received funds), cashback = the last source's (nonce, form)
on target-met and the gap nonce's address in the wallet's receive type
on gap-stop, the pbkdf2 three-purpose-leaf walk, and the vsize fee loop
over witness inputs.

Every chain answer is stubbed per (nonce, form) address, so the tests
run fully offline. Addresses and WIFs pinned below are fixed vectors of
the cascade/pbkdf2 KDFs (same derivations as the Rust side).
"""
import pytest

import yubtc.net
from yubtc.fwd import AddrType

# Fixed vectors: address forms of the cascade KDF (empty passphrase),
# computed from seed2privkey + the three encodings.
SEED_FORMS = 'phase13scanforms'
NATIVE_N1_FORMS = 'bc1qszqwaqfxy3c8mfwfz22e3tns88ye6y79dv34q7'

SEED_GAPFORMS = 'phase13gapforms'
LEGACY_N1_GAPFORMS = '1HoS7MLFvskpYPZnkKVh4VCZ53GjkttqH9'

SEED_CASHBACK = 'phase13cashbackform'
NATIVE_N0_CASHBACK = 'bc1q349ewgk38cenj7ypghc563hx8qsmp76hk8u8g4'

SEED_GAPTYPE = 'phase13gaptype'
TAPROOT_N0_GAPTYPE = 'bc1pvrxletvu9lcvnhmknrvnyuwway3l2xxa7h8ul7zcfxa44q0sjpzs363zv6'

SEED_SKIP_EMPTY = 'scan_skip_used_empty'
LEGACY_N2_SKIP_EMPTY = '17fdyaT3fCab6fiaKDGjkBR4RHHr376ard'

SEED_PBKDF2 = 'phase13pbkdf2scan'
PASSPHRASE = 'phrase'
PBKDF2_NATIVE_N0 = 'bc1qyfmcd9t59mezc3e6704pn4uy704ftfn2jj7rj7'
PBKDF2_NATIVE_N1 = 'bc1qzpqerpwuavg285w8h9lvksq00j3th8ufg3r5yk'

SEED_WALLETGAP = 'phase13walletgap'
TAPROOT_N0_WALLETGAP = 'bc1pfgfnry0vsztaamq6ajqh0t6ljevlkl0kpc05s6ajxzrks37uc40sn0zw5e'

SEED_WALLETNATIVE = 'phase13walletnative'
NATIVE_N0_WALLETNATIVE = 'bc1qsvkxe0npwe0wlaeeg2ss02md9sx4hrndn3uv7u'
LEGACY_N0_WALLETNATIVE = '1CxajpRSkpSZjYpTJqc2NXu5naggSKtEdW'

# txid tag per form (mirrors the Rust mock: `[form.purpose() as u8; 32]`).
_FORM_TAG = {AddrType.LEGACY: 44, AddrType.NATIVE: 84, AddrType.TAPROOT: 86}


def _tp(seed, nonce, passphrase='', addr_type=None):
    from yubtc.wallet import TPrivKey
    if addr_type is None:
        return TPrivKey(seed=seed, nonce=nonce, passphrase=passphrase,
                        backend=object())
    return TPrivKey(seed=seed, nonce=nonce, passphrase=passphrase,
                    backend=object(), addr_type=addr_type)


def _lock_script_for(addr_type, pubkey):
    from yubtc.crypto import taproot_output_key
    from yubtc.hash import hash160
    if addr_type == AddrType.NATIVE:
        return bytes([0x00, 0x14]) + hash160(pubkey)
    if addr_type == AddrType.TAPROOT:
        return bytes([0x51, 0x20]) + taproot_output_key(
            internal_xonly=pubkey[1:33])
    return bytes([0x76, 0xa9, 0x14]) + hash160(pubkey) + bytes([0x88, 0xac])


def _stub_chain(monkeypatch, forms, drained=()):
    """Stub the two net entry points with a per-(nonce, form) chain.

    `forms` is a list of `(seed, nonce, addr_type, amount)` tuples
    (with an optional 5th element: the passphrase, for pbkdf2 forms);
    a form with `amount == 0` is never paid (total_received == 0, the
    v0.1 unused sentinel). `drained` lists `(seed, nonce, addr_type)`
    forms that received funds once but hold no UTXOs any more. A form
    never mentioned answers "unused, no UTXOs", so the walk always
    terminates at a gap.
    """
    info_by_addr = {}
    unspent_by_addr = {}
    for entry in forms:
        seed, nonce, addr_type, amount = entry[:4]
        passphrase = entry[4] if len(entry) > 4 else ''
        pk = _tp(seed, nonce, passphrase=passphrase, addr_type=addr_type)
        info_by_addr[pk.address] = {
            'total_received': amount, 'final_balance': amount,
            'n_tx': 1 if amount else 0,
        }
        unspent_by_addr[pk.address] = (
            [{'tx_hash': ('%02x' % _FORM_TAG[addr_type]) * 32, 'tx_output_n': 0,
              'value': amount, 'confirmations': 6,
              'script': _lock_script_for(addr_type, _pubkey(pk)).hex()}]
            if amount else [])
    # A drained form: received funds once, nothing left to spend.
    for seed, nonce, addr_type in drained:
        address = _tp(seed, nonce, addr_type=addr_type).address
        info_by_addr[address] = {'total_received': 5_000,
                                 'final_balance': 0, 'n_tx': 2}
        unspent_by_addr[address] = []

    def fake_info(backend, address):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        return info_by_addr.get(address,
                                {'total_received': 0, 'final_balance': 0,
                                 'n_tx': 0})

    def fake_unspent(backend, address, **kwargs):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        return list(unspent_by_addr.get(address, []))

    monkeypatch.setattr(yubtc.net, 'get_address_info', fake_info)
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent)


def _pubkey(tp):
    from yubtc.crypto import privkey2pubkey
    return privkey2pubkey(privkey=tp.privkey)


def _wallet(monkeypatch, seed, addr_type=None, passphrase='', new_addresses=0,
            forms=(), drained=()):
    """An offline Wallet over the given `(nonce, form, amount)` chain
    (see `_stub_chain`)."""
    _stub_chain(monkeypatch, forms, drained=drained)
    from yubtc.wallet import Wallet
    if addr_type is None:
        return Wallet(seed=seed, nonce=0, new_addresses=new_addresses,
                      passphrase=passphrase, backend=object())
    return Wallet(seed=seed, nonce=0, new_addresses=new_addresses,
                  passphrase=passphrase, backend=object(), addr_type=addr_type)


# ---------------------------------------------------------------------------
# Multi-form scan: sources, gap rule, cashback (mirrors the Rust scan tests)
# ---------------------------------------------------------------------------

def test_scan_finds_utxos_in_every_form(monkeypatch):
    """One source per contributing (nonce, form), in canonical order.

    Nonce 0: the legacy form was never paid, the native form holds
    1000 sat and the taproot form 2000. Nonce 1: unused -> gap. The
    variant-A form keys are the same secret, so one WIF spends both.
    """
    wallet = _wallet(monkeypatch, SEED_FORMS, addr_type=AddrType.NATIVE,
                     forms=[(SEED_FORMS, 0, AddrType.LEGACY, 0),
                            (SEED_FORMS, 0, AddrType.NATIVE, 1000),
                            (SEED_FORMS, 0, AddrType.TAPROOT, 2000)])
    sources, cashback = wallet._scan_inputs(
        target=None, confirmations=6, on_address=None)
    assert [(pk._addr_type, unspent[0]['amount']) for pk, unspent in sources] == \
        [(AddrType.NATIVE, 1000), (AddrType.TAPROOT, 2000)]
    # Variant A (ОВ-2): same secret in every form -- one WIF spends both.
    assert sources[0][0].get_privwif() == sources[1][0].get_privwif()
    # No target involved -> gap stop at nonce 1, cashback in the
    # wallet's receive form (native).
    assert cashback == NATIVE_N1_FORMS


def test_scan_gap_rule_spans_forms(monkeypatch):
    """A nonce used only through its taproot form is not a gap.

    Nonce 0 was paid only at its `bc1p...` address; the walk must
    include it even for a legacy-typed wallet, then stop at nonce 1.
    """
    wallet = _wallet(monkeypatch, SEED_GAPFORMS, addr_type=AddrType.LEGACY,
                     forms=[(SEED_GAPFORMS, 0, AddrType.TAPROOT, 500)])
    sources, cashback = wallet._scan_inputs(
        target=None, confirmations=6, on_address=None)
    assert len(sources) == 1
    assert sources[0][0]._addr_type == AddrType.TAPROOT
    # Cashback in the wallet's receive form (legacy) at the gap nonce.
    assert cashback == LEGACY_N1_GAPFORMS


def test_scan_cashback_form_is_last_source_form(monkeypatch):
    """Target met: cashback = the last source's (nonce, form).

    The native form of nonce 0 meets the target; the cashback address
    is that native address -- NOT the wallet's receive type (legacy)
    and NOT the gap nonce.
    """
    wallet = _wallet(monkeypatch, SEED_CASHBACK, addr_type=AddrType.LEGACY,
                     forms=[(SEED_CASHBACK, 0, AddrType.NATIVE, 1000)])
    sources, cashback = wallet._scan_inputs(
        target=1000, confirmations=6, on_address=None)
    assert len(sources) == 1
    assert sources[0][0]._addr_type == AddrType.NATIVE
    assert cashback == NATIVE_N0_CASHBACK


def test_scan_cashback_gap_stop_uses_wallet_addr_type(monkeypatch):
    """Gap at nonce 0 (nothing used anywhere): a taproot wallet gets
    its cashback address in the taproot encoding."""
    wallet = _wallet(monkeypatch, SEED_GAPTYPE, addr_type=AddrType.TAPROOT)
    sources, cashback = wallet._scan_inputs(
        target=None, confirmations=6, on_address=None)
    assert sources == []
    assert cashback == TAPROOT_N0_GAPTYPE
    assert cashback.startswith('bc1p')


def test_scan_skips_used_forms_without_utxos(monkeypatch):
    """Used-but-drained forms contribute nothing; funded ones do.

    Nonce 0: legacy drained (received 5000 once, spent), native holds
    700. Only the native form contributes.
    """
    wallet = _wallet(monkeypatch, SEED_FORMS, addr_type=AddrType.NATIVE,
                     forms=[(SEED_FORMS, 0, AddrType.NATIVE, 700)],
                     drained=[(SEED_FORMS, 0, AddrType.LEGACY)])
    sources, _cashback = wallet._scan_inputs(
        target=None, confirmations=6, on_address=None)
    assert len(sources) == 1
    assert sources[0][0]._addr_type == AddrType.NATIVE
    assert sources[0][1][0]['amount'] == 700


def test_scan_continues_past_drained_nonce(monkeypatch):
    """A fully drained nonce is not a gap: the walk reaches nonce 1.

    Mirrors `scan_inputs_until_skips_used_addresses_with_no_utxos`.
    """
    wallet = _wallet(monkeypatch, SEED_SKIP_EMPTY, addr_type=AddrType.LEGACY,
                     forms=[(SEED_SKIP_EMPTY, 1, AddrType.LEGACY, 500)],
                     drained=[(SEED_SKIP_EMPTY, 0, AddrType.LEGACY)])
    sources, cashback = wallet._scan_inputs(
        target=100_000, confirmations=6, on_address=None)
    assert len(sources) == 1
    assert sources[0][0].nonce == 1
    # The unreachable target met -> gap stop at nonce 2.
    assert cashback == LEGACY_N2_SKIP_EMPTY


def test_scan_pbkdf2_walks_three_purpose_leaves(monkeypatch):
    """For pbkdf2 every form is its own BIP-32 leaf: funding the
    m/84' leaf of nonce 0 yields exactly that source, with the m/84'
    WIF (different from the m/44' leaf's)."""
    wallet = _wallet(monkeypatch, SEED_PBKDF2, addr_type=AddrType.NATIVE,
                     passphrase=PASSPHRASE,
                     forms=[(SEED_PBKDF2, 0, AddrType.NATIVE, 900, PASSPHRASE)])
    sources, cashback = wallet._scan_inputs(
        target=None, confirmations=6, on_address=None)
    assert len(sources) == 1
    source_key = sources[0][0]
    assert source_key._addr_type == AddrType.NATIVE
    # The spending key is the m/84' leaf: its WIF differs from the
    # m/44' leaf's (purpose-bound keys).
    legacy_leaf = _tp(SEED_PBKDF2, 0, passphrase=PASSPHRASE,
                      addr_type=AddrType.LEGACY)
    assert source_key.get_privwif() != legacy_leaf.get_privwif()
    assert source_key.address == PBKDF2_NATIVE_N0
    # Gap stop at nonce 1 -> cashback in the wallet's receive type.
    assert cashback == PBKDF2_NATIVE_N1


def test_scan_on_address_fires_per_contributing_form(monkeypatch):
    """`on_address` is invoked once per contributing (nonce, form), in
    scan order, with the form key and its UTXOs."""
    wallet = _wallet(monkeypatch, SEED_FORMS, addr_type=AddrType.NATIVE,
                     forms=[(SEED_FORMS, 0, AddrType.NATIVE, 1000),
                            (SEED_FORMS, 0, AddrType.TAPROOT, 2000)])
    seen = []
    wallet._scan_inputs(
        target=None, confirmations=6,
        on_address=lambda pk, unspent: seen.append(
            (pk.nonce, pk._addr_type, len(unspent))))
    assert seen == [(0, AddrType.NATIVE, 1), (0, AddrType.TAPROOT, 1)]


# ---------------------------------------------------------------------------
# Wallet.__init__ with addr_type: the gap walk spans forms
# ---------------------------------------------------------------------------

def test_wallet_new_gap_walk_spans_forms(monkeypatch):
    """The legacy form of nonce 0 is unused, but its native form is
    used -> Wallet must include the nonce (as the wallet's own type).
    """
    _stub_chain(monkeypatch, [(SEED_WALLETGAP, 0, AddrType.NATIVE, 300)])
    from yubtc.wallet import Wallet
    wallet = Wallet(seed=SEED_WALLETGAP, nonce=0, new_addresses=0,
                    passphrase='', backend=object(), addr_type=AddrType.TAPROOT)
    assert len(wallet.privkeys) == 1
    assert wallet.privkeys[0].nonce == 0
    assert wallet.privkeys[0]._addr_type == AddrType.TAPROOT
    assert wallet.privkeys[0].address == TAPROOT_N0_WALLETGAP


def test_wallet_new_native_type_yields_native_keys(monkeypatch):
    _stub_chain(monkeypatch, [])
    from yubtc.wallet import Wallet
    wallet = Wallet(seed=SEED_WALLETNATIVE, nonce=0, new_addresses=1,
                    passphrase='', backend=object(), addr_type=AddrType.NATIVE)
    assert len(wallet.privkeys) == 1
    assert wallet.privkeys[0]._addr_type == AddrType.NATIVE
    assert wallet.privkeys[0].address == NATIVE_N0_WALLETNATIVE


def test_wallet_default_type_stays_legacy_bit_for_bit(monkeypatch):
    """Omitted addr_type = legacy (the v0.1 constructor, mirroring the
    Rust `TPrivKey::new`): same address the wallet always derived."""
    _stub_chain(monkeypatch, [])
    from yubtc.wallet import Wallet
    wallet = Wallet(seed=SEED_WALLETNATIVE, nonce=0, new_addresses=1,
                    passphrase='', backend=object())
    assert wallet._addr_type == AddrType.LEGACY
    assert wallet.privkeys[0].address == LEGACY_N0_WALLETNATIVE


# ---------------------------------------------------------------------------
# TPrivKey surface: form-aware alias, pbkdf2 purpose guard
# ---------------------------------------------------------------------------

def test_get_p2pkh_address_alias_is_form_aware():
    """The v0.1 alias returns the key's own-form address: legacy bytes
    for a legacy key, the `bc1...` encoding for witness keys (mirrors
    the Rust `get_p2pkh_address` -> `get_address` alias)."""
    legacy = _tp(SEED_WALLETNATIVE, 0)
    assert legacy.get_p2pkh_address() == LEGACY_N0_WALLETNATIVE.encode('ascii')
    native = _tp(SEED_WALLETNATIVE, 0, addr_type=AddrType.NATIVE)
    assert native.get_p2pkh_address() == NATIVE_N0_WALLETNATIVE
    assert native.address == native.address_of()


def test_address_of_pbkdf2_purpose_guard():
    """A pbkdf2 key asked for a different type is refused: m/44'/84'/86'
    are disjoint BIP-32 subtrees, so a re-encoding would name an
    address no external BIP-84/86 wallet agrees with."""
    native = _tp(SEED_PBKDF2, 0, passphrase=PASSPHRASE, addr_type=AddrType.NATIVE)
    with pytest.raises(ValueError, match='purpose-bound'):
        native.address_of(addr_type=AddrType.LEGACY)
    with pytest.raises(ValueError, match='purpose-bound'):
        native.address_of(addr_type=AddrType.TAPROOT)
    # Own type stays fine (the cached address).
    assert native.address_of() == native.address == PBKDF2_NATIVE_N0
    # Variant-A keys re-encode freely.
    variant_a = _tp(SEED_PBKDF2, 0)
    assert variant_a.address_of(addr_type=AddrType.TAPROOT).startswith('bc1p')


def test_nonce_address_forms_pbkdf2_vs_variant_a(monkeypatch):
    """pbkdf2: three distinct leaves; cascade: one key, three forms."""
    from yubtc.wallet import nonce_address_forms
    pbkdf2_forms = nonce_address_forms(seed=SEED_PBKDF2, nonce=0,
                                       passphrase=PASSPHRASE, backend=object())
    assert [form.addr_type for form in pbkdf2_forms] == \
        [AddrType.LEGACY, AddrType.NATIVE, AddrType.TAPROOT]
    wifs = {form.privkey.get_privwif() for form in pbkdf2_forms}
    assert len(wifs) == 3
    native_form = pbkdf2_forms[1]
    assert native_form.address == PBKDF2_NATIVE_N0

    cascade_forms = nonce_address_forms(seed=SEED_PBKDF2, nonce=0,
                                        passphrase='', backend=object())
    wifs = {form.privkey.get_privwif() for form in cascade_forms}
    assert len(wifs) == 1
    assert len({form.address for form in cascade_forms}) == 3


def test_tprivkey_records_its_kdf():
    from yubtc.crypto import KDF_PBKDF2, KDF_YUBTC
    assert _tp(SEED_PBKDF2, 0).kdf == KDF_YUBTC
    assert _tp(SEED_PBKDF2, 0, passphrase=PASSPHRASE).kdf == KDF_PBKDF2


def test_tprivkey_rejects_empty_seed():
    from yubtc.wallet import TPrivKey
    with pytest.raises(ValueError, match='seed cannot be empty'):
        TPrivKey(seed='', nonce=0, passphrase='', backend=object())


def test_wallet_rejects_empty_seed():
    from yubtc.wallet import Wallet
    with pytest.raises(ValueError, match='seed cannot be empty'):
        Wallet(seed='', nonce=0, new_addresses=1, passphrase='',
               backend=object())


def test_make_transaction_with_sources_requires_cashback_addr(monkeypatch):
    """Pre-selected sources without `cashback_addr` are rejected."""
    wallet = _wallet(monkeypatch, SEED_FORMS, addr_type=AddrType.NATIVE,
                     new_addresses=1)
    with pytest.raises(TypeError, match='cashback_addr not set'):
        wallet.make_transaction(
            dst=_tp(SEED_FORMS, 5).address_of(), amount=1000, feekb=1000,
            fee=100, confirmations=6, scan=False,
            sources=[(wallet.privkeys[0], [])], cashback_addr=None,
            on_address=None)


def test_get_unspent_filters_low_confirmation_utxos(monkeypatch):
    """`get_unspent(confirmations=N)` keeps only UTXOs at depth >= N
    (the boundary is inclusive)."""
    from yubtc.crypto import privkey2pubkey
    from yubtc.hash import hash160
    native = _tp(SEED_FORMS, 0, addr_type=AddrType.NATIVE)
    spk = bytes([0x00, 0x14]) + hash160(privkey2pubkey(privkey=native.privkey))
    raw = [{'tx_hash': 'ab' * 32, 'tx_output_n': 0, 'value': 1_000,
            'confirmations': 5, 'script': spk.hex()},
           {'tx_hash': 'cd' * 32, 'tx_output_n': 1, 'value': 2_000,
            'confirmations': 6, 'script': spk.hex()}]

    def fake_unspent(backend, address, **kwargs):
        assert address == native.address
        return list(raw)
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent)
    out = native.get_unspent(confirmations=6)
    assert [u['tx'] for u in out] == ['cd' * 32]


# ---------------------------------------------------------------------------
# End-to-end: multi-form sources -> one signed tx, vsize fee loop
# ---------------------------------------------------------------------------

def test_make_transaction_merges_forms_into_one_signed_tx(monkeypatch):
    """Sources from the legacy and native forms of one nonce sign into
    a single (mixed) transaction paying a `bc1q...` destination."""
    from yubtc.crypto import privkey2pubkey, pubkey2segwit_addr
    from yubtc.hash import hash160
    wallet = _wallet(monkeypatch, SEED_FORMS, addr_type=AddrType.NATIVE,
                     new_addresses=1,
                     forms=[(SEED_FORMS, 0, AddrType.LEGACY, 10_000),
                            (SEED_FORMS, 0, AddrType.NATIVE, 20_000)])
    dst = pubkey2segwit_addr(pubkey=privkey2pubkey(
        privkey=_tp('phase13witdst', 0).privkey))
    result = wallet.make_transaction(
        dst=dst, amount=15_000, feekb=1000, fee=1_000, confirmations=6,
        scan=True, sources=None, cashback_addr=None, on_address=None)
    # Two inputs, one per contributing form; the payment plus the
    # cashback (to the last source's form address, native here).
    assert len(result.tx.vin) == 2
    assert result.amount == 15_000
    assert result.cashback == 14_000
    assert result.fee == 1_000
    assert result.tx.has_witness()
    assert result.tx.serialize_wire() != result.tx.serialize_stripped()
    # The cashback output pays the native form of the last source.
    cashback_script = bytes(result.tx.vout[0].script)
    src_pubkey = privkey2pubkey(privkey=_tp(SEED_FORMS, 0).privkey)
    assert cashback_script == bytes([0x00, 0x14]) + hash160(src_pubkey)
    # The txid ignores the witness (dsha256 of the stripped layout).
    from yubtc.hash import sha256
    assert result.tx.id() == sha256(sha256(result.tx.serialize_stripped()))[::-1]


def test_make_transaction_scan_target_covers_fee(monkeypatch):
    """The scan target is `amount + fee` (the Rust CLI semantics): the
    walk keeps collecting until the inputs cover the payment AND the
    fee."""
    wallet = _wallet(monkeypatch, SEED_SKIP_EMPTY, addr_type=AddrType.LEGACY,
                     new_addresses=1,
                     forms=[(SEED_SKIP_EMPTY, 0, AddrType.LEGACY, 1500),
                            (SEED_SKIP_EMPTY, 1, AddrType.LEGACY, 1500)])
    result = wallet.make_transaction(
        dst=_tp(SEED_SKIP_EMPTY, 5).address_of(), amount=1500, feekb=1000,
        fee=300, confirmations=6, scan=True, sources=None,
        cashback_addr=None, on_address=None)
    # amount-only targeting would stop after nonce 0 (1500 >= 1500);
    # amount + fee needs nonce 1 too.
    assert len(result.tx.vin) == 2


def test_make_transaction_fee_loop_bills_vsize(monkeypatch):
    """fee=0 drives the fee loop; for a witness transaction the fee is
    `vsize * feekb / 1000` -- the witness bytes weigh 1/4 (mirrors
    `fee_loop_on_witness_tx_bills_vsize_not_bytes`)."""
    wallet = _wallet(monkeypatch, SEED_FORMS, addr_type=AddrType.NATIVE,
                     new_addresses=1,
                     forms=[(SEED_FORMS, 0, AddrType.NATIVE, 500_000)])
    from yubtc.crypto import privkey2pubkey, pubkey2taproot_addr
    dst = pubkey2taproot_addr(pubkey=privkey2pubkey(
        privkey=_tp('phase13witdst', 0).privkey))
    result = wallet.make_transaction(
        dst=dst, amount=250_000, feekb=1000, fee=0, confirmations=6,
        scan=True, sources=None, cashback_addr=None, on_address=None)
    assert result.tx.has_witness()
    assert len(result.tx.serialize_wire()) > len(result.tx.serialize_stripped())
    assert result.fee == result.tx.vsize() * 1000 // 1000
    # The witness discount is visible: vsize bills below the wire size.
    assert result.tx.vsize() < len(result.tx.serialize_wire())
