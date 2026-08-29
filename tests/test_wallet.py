"""Tests for wallet.py: TPrivKey and Wallet.

These pin the wallet's contract: how kwargs are validated, how the
seed-scan loop in `Wallet.__init__` walks nonces, how get_info caches,
how get_unspent filters by confirmations, and how the send/make_transaction
flow assembles a signed tx from one or more UTXOs.

Backend injection (Phase 13): every TPrivKey/Wallet is constructed with an
explicit `backend=` handle, and the net entry points are monkeypatched with
their current `(backend, address)` signature. The multi-form scan (spec
ОВ-4) queries P2PKH + P2WPKH + P2TR per nonce, so "used" stubs mark all
three forms of a nonce.

The blockchain.info calls are stubbed per-test via `monkeypatch`.
"""
import pytest
from decimal import Decimal
from unittest.mock import MagicMock

import yubtc
import yubtc.net
from yubtc.wallet import TxResult

# Inert backend handle: the wallet stores it and threads it into the
# (monkeypatched) net free functions, so it is never used for I/O.
# Backend injection requires passing it explicitly -- the kwargs-only
# wrapper rejects an omitted `backend=` kwarg.
_BACKEND = object()


def _all_form_addresses(seed, nonces, passphrase=''):
    """Every address form (P2PKH/P2WPKH/P2TR) of `(seed, nonces)`.

    The multi-form scan queries all three forms per nonce, so stubs
    that answer per-address need the full form set of each nonce.
    """
    from yubtc.crypto import (privkey2pubkey, pubkey2addr,
                              pubkey2segwit_addr, pubkey2taproot_addr,
                              seed2privkey)
    addresses = set()
    for nonce in nonces:
        pubkey = privkey2pubkey(
            privkey=seed2privkey(seed=seed, nonce=nonce,
                                 passphrase=passphrase))
        addresses.add(pubkey2addr(pubkey=pubkey).decode('ascii'))
        addresses.add(pubkey2segwit_addr(pubkey=pubkey))
        addresses.add(pubkey2taproot_addr(pubkey=pubkey))
    return addresses


def stub_used_nonces(monkeypatch, nonces):
    """Mark every address form of `nonces` as used (received funds).

    The gap rule generalised to nonces (Phase 13): a nonce is used when
    ANY of its forms has `total_received > 0`. Marking all three forms
    keeps the stub consistent regardless of which form is queried.
    """
    used = _all_form_addresses('qwe', nonces)

    def fake_info(backend, address):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        if address in used:
            return {'total_received': 1, 'final_balance': 0, 'n_tx': 1}
        return {'total_received': 0, 'final_balance': 0, 'n_tx': 0}

    monkeypatch.setattr('yubtc.net.get_address_info', fake_info)


# ---------------------------------------------------------------------------
# TPrivKey: kwargs-only construction.
# ---------------------------------------------------------------------------

def test_TPrivKey_rejects_positional_args():
    """`TPrivKey(arg, passphrase='')` is invalid -- only kwargs are accepted."""
    from yubtc.wallet import TPrivKey
    with pytest.raises(TypeError, match='only kwargs allowed'):
        TPrivKey('positional', passphrase='')


def test_TPrivKey_derives_privkey_from_seed_and_nonce():
    """`seed=...` + `nonce=...` -> privkey via seed2privkey."""
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey
    p = TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    assert p.privkey == seed2privkey(seed='qwe', nonce=0, passphrase='')
    assert p.nonce == 0


def test_TPrivKey_passphrase_changes_privkey():
    """Two nonces with different passphrases must derive distinct keys;
    the parameter is forwarded into the KDF, not silently dropped."""
    from yubtc.wallet import TPrivKey
    a = TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    b = TPrivKey(seed='qwe', nonce=0, passphrase='hunter2', backend=_BACKEND)
    assert a.privkey != b.privkey


def test_TPrivKey_requires_seed():
    """No privkey and no seed -> exception."""
    from yubtc.wallet import TPrivKey
    with pytest.raises(TypeError, match='seed not set'):
        TPrivKey(nonce=0, passphrase='')


def test_TPrivKey_rejects_empty_seed():
    """An empty seed string is rejected -- it's distinct from "not set"."""
    from yubtc.wallet import TPrivKey
    with pytest.raises(ValueError, match='seed cannot be empty'):
        TPrivKey(seed='', nonce=0, passphrase='', backend=_BACKEND)


def test_TPrivKey_requires_nonce():
    """seed but no nonce -> exception."""
    from yubtc.wallet import TPrivKey
    with pytest.raises(TypeError, match='nonce not set'):
        TPrivKey(seed='qwe', passphrase='')


# ---------------------------------------------------------------------------
# TPrivKey: derived helpers.
# ---------------------------------------------------------------------------

def test_TPrivKey_get_privwif():
    """WIF is the compressed form (Bitcoin convention)."""
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey, privkey2privwif
    p = TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    assert p.get_privwif() == privkey2privwif(
        privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))


def test_TPrivKey_get_p2pkh_address():
    """Address derivation reuses privkey2addr."""
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey, privkey2addr
    p = TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    assert p.get_p2pkh_address() == privkey2addr(
        privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))


# ---------------------------------------------------------------------------
# TPrivKey.get_info: caches the network call.
# ---------------------------------------------------------------------------

def test_TPrivKey_get_info_caches(monkeypatch):
    """get_info calls the network once and caches the result in `_info`."""
    from yubtc.wallet import TPrivKey
    calls = []

    def fake_info(backend, address):
        calls.append(address)
        return {'total_received': 0, 'final_balance': 0, 'n_tx': 0}
    monkeypatch.setattr(yubtc.net, 'get_address_info', fake_info)

    p = TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    a = p.get_info()
    b = p.get_info()
    assert a is b
    assert len(calls) == 1


def test_TPrivKey_get_info_returns_cached_dict(monkeypatch):
    """The cached dict is returned, not re-fetched."""
    from yubtc.wallet import TPrivKey
    monkeypatch.setattr(yubtc.net, 'get_address_info',
                        lambda backend, address: {'total_received': 1, 'n_tx': 1})
    p = TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    assert p.get_info() == {'total_received': 1, 'n_tx': 1}


# ---------------------------------------------------------------------------
# TPrivKey.is_unused: total_received == 0
# ---------------------------------------------------------------------------

def test_TPrivKey_is_unused_when_total_received_is_zero(monkeypatch):
    import yubtc.wallet
    monkeypatch.setattr(yubtc.net, 'get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    assert p.is_unused() is True


def test_TPrivKey_is_used_when_total_received_is_nonzero(monkeypatch):
    import yubtc.wallet
    monkeypatch.setattr(yubtc.net, 'get_address_info',
                        lambda backend, address: {'total_received': 1, 'n_tx': 1})
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    assert p.is_unused() is False


# ---------------------------------------------------------------------------
# TPrivKey.get_unspent: filters by confirmations and renames the API fields.
# ---------------------------------------------------------------------------

def test_TPrivKey_get_unspent_returns_empty_when_no_utxos(monkeypatch):
    import yubtc.wallet
    monkeypatch.setattr(yubtc.net, 'get_address_unspent',
                        lambda backend, address, **kwargs: [])
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    assert p.get_unspent(confirmations=0) == []


def test_TPrivKey_get_unspent_renames_api_fields(monkeypatch):
    """The blockchain.info format uses tx_hash / tx_output_n / value / script.
    The wallet's internal format renames these to tx / out_n / amount / script,
    and passes `confirmations` through so callers (notably the TUI) can
    show how deep each input sits in the chain."""
    import yubtc.wallet
    raw = [{'tx_hash': 'a' * 64, 'tx_output_n': 0, 'value': 50_000,
            'confirmations': 10, 'script': '76a914' + 'aa' * 20 + '88ac'}, ]
    monkeypatch.setattr(yubtc.net, 'get_address_unspent',
                        lambda backend, address, **kwargs: raw)
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    out = p.get_unspent(confirmations=0)
    assert out == [
        {'tx': 'a' * 64, 'out_n': 0, 'amount': 50_000, 'script': '76a914' + 'aa' * 20 + '88ac',
         'confirmations': 10},
    ]


def test_TPrivKey_get_unspent_filters_low_confirmation_utxos(monkeypatch):
    import yubtc.wallet
    raw = [{'tx_hash': 'a' * 64,
            'tx_output_n': 0,
            'value': 50_000,
            'confirmations': 1,
            'script': '76a914' + 'aa' * 20 + '88ac'},
           {'tx_hash': 'b' * 64,
            'tx_output_n': 1,
            'value': 50_000,
            'confirmations': 10,
            'script': '76a914' + 'bb' * 20 + '88ac'},
           ]
    monkeypatch.setattr(yubtc.net, 'get_address_unspent',
                        lambda backend, address, **kwargs: raw)
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    out = p.get_unspent(confirmations=5)
    assert len(out) == 1
    assert out[0]['tx'] == 'b' * 64


def test_TPrivKey_get_unspent_includes_equal_confirmation(monkeypatch):
    """Boundary: confirmations >= threshold (inclusive)."""
    import yubtc.wallet
    raw = [{'tx_hash': 'a' * 64, 'tx_output_n': 0, 'value': 50_000,
            'confirmations': 5, 'script': '76a914' + 'aa' * 20 + '88ac'}, ]
    monkeypatch.setattr(yubtc.net, 'get_address_unspent',
                        lambda backend, address, **kwargs: raw)
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    assert len(p.get_unspent(confirmations=5)) == 1


def test_TPrivKey_get_unspent_raises_when_confirmations_missing():
    """get_unspent's `confirmations` is required -- callers must pass it."""
    import yubtc.wallet
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    with pytest.raises(TypeError, match='confirmations not set'):
        p.get_unspent()


# ---------------------------------------------------------------------------
# Wallet: kwargs-only construction.
# ---------------------------------------------------------------------------

def test_Wallet_rejects_positional_args():
    from yubtc.wallet import Wallet
    with pytest.raises(TypeError, match='only kwargs allowed'):
        Wallet('positional', passphrase='')


def test_Wallet_send_rejects_positional_args(monkeypatch):
    """send(arg, ...) is invalid -- only kwargs are accepted."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr(yubtc.net, 'get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    with pytest.raises(TypeError, match='only kwargs allowed'):
        w.send('positional')


def test_Wallet_from_seed_stops_at_first_unused_address(monkeypatch):
    """The seed-scan loop terminates when an unused address is found."""
    from yubtc.wallet import Wallet
    # Every form of nonce 0 has received funds; nonce 1 is fresh.
    stub_used_nonces(monkeypatch, [0])
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda backend, address, **kwargs: [])

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    # Walked over nonce 0 (used), then nonce 1 (fresh) -> stop.
    assert len(w.privkeys) == 2
    assert w.privkeys[0].nonce == 0
    assert w.privkeys[1].nonce == 1


def test_Wallet_from_seed_with_new_addresses(monkeypatch):
    """`new_addresses=N` follows the seed scan with N additional fresh addresses.

    The scan walks past any used addresses and breaks at the first unused one.
    Then `new_addresses` fresh addresses are appended starting from that nonce.
    """
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda backend, address, **kwargs: [])

    w = Wallet(seed='qwe', nonce=0, new_addresses=3, passphrase='', backend=_BACKEND)
    # Nonce 0 is the first unused (no scan); then 3 fresh addresses appended.
    assert len(w.privkeys) == 3
    assert [p.nonce for p in w.privkeys] == [0, 1, 2]


def test_Wallet_from_seed_scan_then_appends(monkeypatch):
    """Scanned used addresses plus new_addresses fresh ones."""
    from yubtc.wallet import Wallet
    # Every form of nonces 0 and 1 has received funds; nonce 2 is fresh.
    stub_used_nonces(monkeypatch, [0, 1])
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        lambda backend, address, **kwargs: [])

    w = Wallet(seed='qwe', nonce=0, new_addresses=2, passphrase='', backend=_BACKEND)
    # Nonces 0,1 used (appended); nonce 2 is the first fresh (dropped); then
    # `new_addresses=2` more appended starting at nonce 2.
    assert len(w.privkeys) == 4
    assert [p.nonce for p in w.privkeys] == [0, 1, 2, 3]


# ---------------------------------------------------------------------------
# Wallet.send: builds a tx, asks yes/no, prints or sends.
# ---------------------------------------------------------------------------

def test_Wallet_send_dry_run_prints_raw_tx(monkeypatch, monkeypatch_input):
    """With broadcast=False the dump (id + summary + raw tx hex) is printed; broadcastTx is not called."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())

    sent = MagicMock()
    import yubtc.net
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    out = dry_run_send(w, monkeypatch_input, dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount='0.0005')
    assert 'id: ' in out
    assert 'rawtx: ' in out
    sent.assert_not_called()


def test_Wallet_send_with_amount_none_skips_btc2satoshi(monkeypatch, monkeypatch_input):
    """When amount=None, the wallet doesn't call btc2satoshi on it.

    Exercises the `if amount is not None:` short-circuit in Wallet.send.
    """
    from yubtc.wallet import Wallet
    import yubtc.net
    import yubtc.misc
    monkeypatch.setattr(yubtc.net, 'get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent_with_one_utxo())
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    out = dry_run_send(w, monkeypatch_input, dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=None)
    assert out is not None  # drained all funds; tx still printed
    sent.assert_not_called()


def test_Wallet_send_with_broadcast_calls_broadcastTx(monkeypatch, monkeypatch_input):
    """With broadcast=True, the tx is passed to net.broadcastTx."""
    """With broadcast=True, the tx is passed to net.broadcastTx."""
    from yubtc.wallet import Wallet
    import yubtc.net
    import yubtc.misc
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    dry_run_send(w, monkeypatch_input, dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount='0.0005', broadcast=True)
    sent.assert_called_once()


def test_Wallet_send_declined_prints_nothing(monkeypatch):
    """With --broadcast, answering 'n' to the prompt skips broadcastTx; the dump still prints."""
    from yubtc.wallet import Wallet
    import yubtc.net
    import yubtc.misc

    monkeypatch.setattr(yubtc.net, 'get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent_with_one_utxo())
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)

    # monkeypatch the yes/no prompt to decline.
    monkeypatch.setattr(yubtc.misc, 'yesno', lambda q: False)

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    from decimal import Decimal
    w.send(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=Decimal('0.0005'),
           fee=Decimal('0.00001'), feekb=2_000, confirmations=0, broadcast=True, scan=False,
           on_address=None, yes=False)
    sent.assert_not_called()


def test_Wallet_send_dry_run_does_not_prompt(monkeypatch):
    """Without --broadcast the dump prints; no confirmation is asked."""
    from yubtc.wallet import Wallet
    import yubtc.net
    import yubtc.misc

    monkeypatch.setattr(yubtc.net, 'get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent_with_one_utxo())
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)

    prompted = []
    monkeypatch.setattr(yubtc.misc, 'yesno', lambda q: (prompted.append(q), True)[1])

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    from decimal import Decimal
    w.send(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=Decimal('0.0005'),
           fee=Decimal('0.00001'), feekb=2_000, confirmations=0, broadcast=False, scan=False,
           on_address=None, yes=False)
    assert prompted == []
    sent.assert_not_called()


def test_Wallet_send_with_yes_skips_broadcast_prompt(monkeypatch):
    """`yes=True` skips the broadcast confirmation prompt and broadcasts directly.

    The yesno fixture is patched with a MagicMock so we can assert it
    was never invoked. broadcastTx is then called exactly once.
    """
    from yubtc.wallet import Wallet
    import yubtc.net
    import yubtc.misc
    from unittest.mock import MagicMock
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())
    prompted = MagicMock(side_effect=AssertionError('yesno called despite yes=True'))
    monkeypatch.setattr(yubtc.misc, 'yesno', prompted)

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    from decimal import Decimal
    w.send(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=Decimal('0.0005'),
           fee=Decimal('0.00001'), feekb=2_000, confirmations=0,
           broadcast=True, scan=False, on_address=None, yes=True)
    prompted.assert_not_called()
    sent.assert_called_once()


def test_Wallet_send_with_yes_and_no_broadcast_does_nothing(monkeypatch):
    """`yes=True` without `broadcast=True` is a no-op -- no prompt, no broadcast."""
    from yubtc.wallet import Wallet
    import yubtc.net
    import yubtc.misc
    from unittest.mock import MagicMock
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())
    prompted = MagicMock(side_effect=AssertionError('yesno called despite broadcast=False'))
    monkeypatch.setattr(yubtc.misc, 'yesno', prompted)

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    from decimal import Decimal
    w.send(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=Decimal('0.0005'),
           fee=Decimal('0.00001'), feekb=2_000, confirmations=0,
           broadcast=False, scan=False, on_address=None, yes=True)
    prompted.assert_not_called()
    sent.assert_not_called()


def test_Wallet_send_raises_when_required_arg_missing(monkeypatch, monkeypatch_input):
    """Wallet.send raises when a required kwarg is omitted (None == not passed).

    `amount` is the exception: it stays None to mean "drain all available funds".
    """
    from yubtc.wallet import Wallet
    import yubtc.net
    import yubtc.misc
    monkeypatch.setattr(yubtc.net, 'get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.net, 'get_address_unspent', fake_unspent_with_one_utxo())
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    base = dict(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k',
                amount=None, fee=Decimal('0.00001'), feekb=2_000,
                confirmations=0, broadcast=False, scan=False, on_address=None, yes=False)
    with pytest.raises(TypeError, match='dst not set'):
        w.send(**{k: v for k, v in base.items() if k != 'dst'})
    with pytest.raises(TypeError, match='fee not set'):
        w.send(**{k: v for k, v in base.items() if k != 'fee'})
    with pytest.raises(TypeError, match='feekb not set'):
        w.send(**{k: v for k, v in base.items() if k != 'feekb'})
    with pytest.raises(TypeError, match='confirmations not set'):
        w.send(**{k: v for k, v in base.items() if k != 'confirmations'})
    with pytest.raises(TypeError, match='broadcast not set'):
        w.send(**{k: v for k, v in base.items() if k != 'broadcast'})
    with pytest.raises(TypeError, match='scan not set'):
        w.send(**{k: v for k, v in base.items() if k != 'scan'})
    with pytest.raises(TypeError, match='yes not set'):
        w.send(**{k: v for k, v in base.items() if k != 'yes'})


def test_Wallet_init_raises_when_seed_missing(monkeypatch):
    """Wallet.__init__ requires `seed`; None raises."""
    from yubtc.wallet import Wallet
    with pytest.raises(TypeError, match='seed not set'):
        Wallet(new_addresses=1, passphrase='')


def test_Wallet_init_raises_when_new_addresses_missing(monkeypatch):
    """Wallet.__init__ requires `new_addresses`; None raises."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', lambda backend, address, **kwargs: [])
    with pytest.raises(TypeError, match='new_addresses not set'):
        Wallet(seed='qwe', nonce=0, passphrase='')


def test_Wallet_rejects_empty_seed(monkeypatch):
    """Empty seed string is rejected (distinct from "not set")."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', lambda backend, address, **kwargs: [])
    with pytest.raises(ValueError, match='seed cannot be empty'):
        Wallet(seed='', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)


# ---------------------------------------------------------------------------
# Wallet._make_vin: builds inputs from UTXOs.
# ---------------------------------------------------------------------------

def test_Wallet_make_vin_builds_cin_for_each_utxo(monkeypatch):
    """Each unspent UTXO becomes a CIn with the right txhash, n, and script."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_two_utxos())

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    tp = w.privkeys[0]
    unspent = tp.get_unspent(confirmations=0)
    # Phase 13: `_make_vin` returns a 4-tuple -- the `(privkey, pubkey)`
    # signer pairs are now joined by a parallel `SpendContext` list that
    # carries the BIP-143/BIP-341 signing inputs.
    vin, in_amount, signers, spend = w._make_vin(sources=[(tp, unspent)])
    assert in_amount == 100_000
    assert len(vin) == 2
    assert vin[0].txhash == b'\xaa' * 32
    assert vin[0].n == 0
    assert vin[1].txhash == b'\xbb' * 32
    assert vin[1].n == 1
    assert len(spend) == 2


def test_Wallet_make_vin_rejects_utxo_with_mismatched_pubkey(monkeypatch):
    """A UTXO whose lock script doesn't match the source privkey's pubhash is rejected."""
    from yubtc.wallet import Wallet, TPrivKey
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', lambda backend, address, **kwargs: [])

    tp = TPrivKey(seed='qwe', nonce=0, passphrase='', backend=_BACKEND)
    # Lock script for a different pubhash than tp's -- a random 20-byte payload.
    bad_script = '76a914' + '11' * 20 + '88ac'
    bad_utxo = [{'tx': 'a' * 64, 'out_n': 0, 'amount': 1_000, 'script': bad_script}]
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    with pytest.raises(ValueError, match='unknown pubkey required'):
        w._make_vin(sources=[(tp, bad_utxo)])


# ---------------------------------------------------------------------------
# Wallet.make_transaction: builds and signs a tx.
# ---------------------------------------------------------------------------

def test_Wallet_make_transaction_drains_input_when_amount_is_none(monkeypatch):
    """amount=None -> no change output; all funds go to the destination."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo(amount=100_000))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=None, fee=1_000,
        feekb=2000, confirmations=0, scan=False,
        sources=None, cashback_addr=None, on_address=None,
    )
    assert result.cashback == 0
    assert result.amount == 99_000
    assert len(result.tx.vout) == 1
    assert result.tx.vout[0].amount == 99_000


def test_Wallet_make_transaction_drains_when_amount_plus_fee_equals_input(monkeypatch):
    """Explicit drain: amount + fee == in_amount."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo(amount=100_000))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=99_000, fee=1_000,
        feekb=2000, confirmations=0, scan=False,
        sources=None, cashback_addr=None, on_address=None,
    )
    assert result.cashback == 0
    assert len(result.tx.vout) == 1


def test_Wallet_make_transaction_adds_change_output(monkeypatch):
    """amount + fee < in_amount -> a change output back to the source."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo(amount=100_000))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=1_000,
        feekb=2000, confirmations=0, scan=False,
        sources=None, cashback_addr=None, on_address=None,
    )
    assert result.cashback == 49_000
    assert result.amount == 50_000
    assert len(result.tx.vout) == 2
    # Output order: change first, then payment.
    assert result.tx.vout[0].amount == 49_000
    assert result.tx.vout[1].amount == 50_000


def test_Wallet_make_transaction_signs_with_owners_privkey(monkeypatch):
    """The signed tx's input scripts use the wallet's owner privkey."""
    from yubtc.wallet import Wallet
    from yubtc.crypto import seed2privkey, privkey2pubkey
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo(amount=100_000))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=1_000,
        feekb=2000, confirmations=0, scan=False,
        sources=None, cashback_addr=None, on_address=None,
    )
    pubwif = privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    # The signed signature script ends with the pubwif.
    assert result.tx.vin[0].script.endswith(pubwif)


def test_Wallet_make_transaction_recurses_until_fee_is_stable(monkeypatch):
    """When fee is not provided, the loop iterates until the fee rate is stable."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo(amount=200_000))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    # Use feekb so the fee is set iteratively; no fixed fee.
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=0, feekb=2000,
        confirmations=0, scan=False,
        sources=None, cashback_addr=None, on_address=None,
    )
    # txsize is small enough that the second iteration converges.
    assert result.fee > 0
    # The cashback + amount + fee equals the in_amount.
    assert result.cashback + result.amount + result.fee == 200_000


def test_Wallet_make_transaction_raises_when_confirmations_or_feekb_missing(monkeypatch):
    """make_transaction requires `confirmations` and `feekb`; `fee` may be None."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    base = dict(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000,
                fee=1_000, feekb=2_000, confirmations=0, scan=False)
    with pytest.raises(TypeError, match='confirmations not set'):
        w.make_transaction(**{k: v for k, v in base.items() if k != 'confirmations'})
    with pytest.raises(TypeError, match='feekb not set'):
        w.make_transaction(**{k: v for k, v in base.items() if k != 'feekb'})


def test_Wallet_make_transaction_raises_when_dst_missing(monkeypatch):
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    base = dict(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000,
                fee=1_000, feekb=2_000, confirmations=0, scan=False)
    with pytest.raises(TypeError, match='dst not set'):
        w.make_transaction(**{k: v for k, v in base.items() if k != 'dst'})


def test_Wallet_make_vin_raises_when_sources_missing(monkeypatch):
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', lambda backend, address, **kwargs: [])
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    with pytest.raises(TypeError, match='sources not set'):
        w._make_vin()


def test_Wallet_methods_reject_positional_args(monkeypatch):
    """send / make_transaction / _make_vin all require kwargs-only calls."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    # send: positional dst is no longer allowed -- 'only kwargs allowed'.
    with pytest.raises(TypeError, match='only kwargs allowed'):
        w.send('1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    # make_transaction: same.
    with pytest.raises(TypeError, match='only kwargs allowed'):
        w.make_transaction('1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 50_000)
    # _make_vin: same.
    with pytest.raises(TypeError, match='only kwargs allowed'):
        w._make_vin([])


# ---------------------------------------------------------------------------
# Helpers (test-local).
# ---------------------------------------------------------------------------


def test_Wallet_make_transaction_uses_caller_sources_and_cashback_addr(monkeypatch):
    """End-to-end: pre-selected sources + cashback_addr reach make_vout
    and the tx is built/signed."""
    from yubtc.wallet import Wallet
    from yubtc.crypto import seed2privkey, privkey2addr, privkey2pubkey
    from yubtc.hash import hash160
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    pk = w.privkeys[0]
    pubkey = privkey2pubkey(privkey=pk.privkey)
    pubhash = hash160(pubkey)
    script = '76a914' + pubhash.hex() + '88ac'
    sources = [(pk, [{'tx': 'aa' * 32, 'out_n': 0, 'amount': 100_000,
                      'confirmations': 10, 'script': script}])]
    # Use the gap-limit address as the cashback destination. Phase 13
    # convention: addresses are `str` end to end (the multi-form wallet
    # also handles `bc1...`, which has no bytes form).
    cashback = privkey2addr(
        privkey=seed2privkey(seed='qwe', nonce=2, passphrase='')).decode('ascii')
    stx_result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=99_000, fee=1_000,
        feekb=2_000, confirmations=0, scan=False,
        sources=sources, cashback_addr=cashback, on_address=None,
    )
    # Exact spend: no cashback, single output.
    assert stx_result.cashback == 0
    assert stx_result.amount == 99_000
    assert len(stx_result.tx.vout) == 1


def test_Wallet_make_transaction_with_sources_requires_cashback_addr(monkeypatch):
    """When `sources` is provided, `cashback_addr` is also required."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    with pytest.raises(TypeError, match='cashback_addr not set'):
        w.make_transaction(
            dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000,
            fee=1_000, feekb=2_000, confirmations=0, scan=False,
            sources=[(w.privkeys[0], [{'tx_hash': 'aa' * 32, 'out_n': 0,
                                       'amount': 100_000, 'confirmations': 0,
                                       'script': '76a914' + 'aa' * 20 + '88ac'}])],
            cashback_addr=None, on_address=None,
        )


@pytest.fixture
def monkeypatch_input(monkeypatch):
    """Patch `yubtc.misc.yesno` to confirm everything."""
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'yesno', lambda q: True)


def dry_run_send(w, input_fixture, dst, amount, broadcast=False, scan=False, yes=False):
    """Run wallet.send with the local yes/no fixture and capture stdout.

    `amount` is in BTC (the wallet's TBTC units). It is converted to a Decimal
    so btc2satoshi treats it as BTC, not satoshi. Pass amount=None to send all.
    The dump (id, summary, rawtx) is always printed; returns it.

    `yes=True` skips the broadcast confirmation prompt -- the helper
    leaves the no-op yesno fixture in place but `Wallet.send` won't
    call it.
    """
    from decimal import Decimal
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    btc_amount = Decimal(amount) if amount is not None else None
    with redirect_stdout(buf):
        w.send(dst=dst, amount=btc_amount, fee=Decimal('0.00001'), feekb=2_000,
               confirmations=0, broadcast=broadcast, scan=scan, on_address=None, yes=yes)
    return buf.getvalue()


def fake_unspent_with_one_utxo(amount=100_000):
    """A one-UTXO unspent list whose lock script matches the qwe seed."""
    from yubtc.crypto import seed2privkey, privkey2pubkey
    from yubtc.hash import hash160
    pubwif = privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    pubhash = hash160(pubwif)
    # P2PKH lock script: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
    script = '76a914' + pubhash.hex() + '88ac'
    raw = [
        {'tx_hash': 'a' * 64, 'tx_output_n': 0, 'value': amount, 'confirmations': 10, 'script': script},
    ]
    return lambda backend, address, **kwargs: raw


def fake_unspent_with_two_utxos():
    """Two UTXOs for the same address."""
    from yubtc.crypto import seed2privkey, privkey2pubkey
    from yubtc.hash import hash160
    pubwif = privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    pubhash = hash160(pubwif)
    script = '76a914' + pubhash.hex() + '88ac'
    raw = [
        {'tx_hash': 'aa' * 32, 'tx_output_n': 0, 'value': 50_000, 'confirmations': 10, 'script': script},
        {'tx_hash': 'bb' * 32, 'tx_output_n': 1, 'value': 50_000, 'confirmations': 10, 'script': script},
    ]
    return lambda backend, address, **kwargs: raw


def _p2pkh_script_for_seed(seed: str, nonce: int) -> str:
    """Build the P2PKH lock script hex for (seed, nonce)."""
    from yubtc.crypto import seed2privkey, privkey2pubkey
    from yubtc.hash import hash160
    pubwif = privkey2pubkey(privkey=seed2privkey(seed=seed, nonce=nonce, passphrase=''))
    pubhash = hash160(pubwif)
    return '76a914' + pubhash.hex() + '88ac'


def fake_unspent_per_nonce(specs):
    """Return a fake `get_address_unspent` mapping nonce -> UTXO list.

    `specs` is a dict `{nonce: [amount, ...]}`. Any nonce not in the
    dict returns an empty list (used to test the gap-limit stop).

    The UTXOs are locked to the canonical P2PKH form of each (seed,
    nonce) pair, so only the P2PKH form of a used nonce contributes
    inputs -- the P2WPKH/P2TR forms of the same nonce are used-but-empty
    per `stub_used_nonces` and contribute nothing.
    """
    from yubtc.crypto import seed2privkey, privkey2addr

    def addr_for_nonce(nonce):
        return privkey2addr(privkey=seed2privkey(seed='qwe', nonce=nonce, passphrase='')).decode('ascii')

    nonce_to_addr = {n: addr_for_nonce(n) for n in specs}

    def get_unspent(backend, address, **kwargs):
        address = address.decode('ascii') if isinstance(address, bytes) else address
        for n, a in nonce_to_addr.items():
            if a == address:
                script = _p2pkh_script_for_seed('qwe', n)
                return [
                    {'tx_hash': f'{n:064x}'[-64:], 'tx_output_n': i,
                     'value': amt, 'confirmations': 10, 'script': script}
                    for i, amt in enumerate(specs[n])
                ]
        return []
    return get_unspent


# ---------------------------------------------------------------------------
# Wallet.send(scan=True): walk forward collecting addresses' UTXOs.
# ---------------------------------------------------------------------------

def test_Wallet_make_transaction_scan_stops_at_unused_address(monkeypatch):
    """Scan halts when the next nonce's every form is unused (gap limit)."""
    from yubtc.wallet import Wallet
    # Nonces 0 and 1 are used (P2PKH form holds the UTXOs); nonce 2 is
    # an all-forms gap -> stop.
    stub_used_nonces(monkeypatch, [0, 1])
    # Target (80_000 + fee) > each nonce's balance, so both are needed.
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [60_000], 1: [60_000]}))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=80_000, fee=1_000,
        feekb=2_000, confirmations=0, scan=True,
        sources=None, cashback_addr=None, on_address=None,
    )
    # Two addresses scanned, both contributed one input.
    assert len(result.tx.vin) == 2
    # Total in = 120_000, amount + fee = 81_000, cashback = 39_000.
    assert result.cashback + result.amount + result.fee == 120_000
    assert result.amount == 80_000


def test_Wallet_make_transaction_scan_stops_at_target(monkeypatch):
    """Scan halts when the running total reaches the target amount."""
    from yubtc.wallet import Wallet
    stub_used_nonces(monkeypatch, [0, 1, 2])
    # Nonces 0, 1, 2 all have UTXOs of 30_000 each. The scan target is
    # amount + fee (current Rust-parity semantics: inputs must cover
    # the payment AND the fee) = 51_000 -> stop after nonce 1
    # (total = 60_000 >= 51_000), nonce 2 never queried for UTXOs.
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [30_000], 1: [30_000], 2: [30_000]}))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=1_000,
        feekb=2_000, confirmations=0, scan=True,
        sources=None, cashback_addr=None, on_address=None,
    )
    assert len(result.tx.vin) == 2
    assert result.cashback + result.amount + result.fee == 60_000


def test_Wallet_make_transaction_scan_with_all_drains(monkeypatch):
    """scan=True + amount=None drains every collected UTXO."""
    from yubtc.wallet import Wallet
    stub_used_nonces(monkeypatch, [0, 1])
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [40_000], 1: [40_000]}))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=None, fee=1_000,
        feekb=2_000, confirmations=0, scan=True,
        sources=None, cashback_addr=None, on_address=None,
    )
    # amount=None + scan drains what's collected; cashback=0.
    assert result.cashback == 0
    assert result.amount == 80_000 - result.fee
    assert len(result.tx.vout) == 1
    assert result.tx.vout[0].amount == 80_000 - result.fee


def test_Wallet_scan_change_goes_to_unused_address_at_gap(monkeypatch):
    """When scan halts via gap limit, cashback goes to the unused address."""
    from yubtc.wallet import Wallet
    from yubtc.crypto import seed2privkey, privkey2addr
    # Nonces 0 and 1 are used (P2PKH form holds the UTXOs); nonce 2 is
    # the all-forms gap -> stop.
    stub_used_nonces(monkeypatch, [0, 1])
    # The target is intentionally unreachable so the scan stops at the gap.
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [60_000], 1: [60_000]}))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    sources, cashback_addr = w._scan_inputs(target=200_000, confirmations=0, on_address=None)

    assert len(sources) == 2
    # Phase 13: the cashback address is a `str` for every form (the
    # gap nonce's address in the wallet's own receive type -- legacy
    # here, since no addr_type was given).
    unused_addr = privkey2addr(
        privkey=seed2privkey(seed='qwe', nonce=2, passphrase='')).decode('ascii')
    assert cashback_addr == unused_addr


def test_Wallet_scan_continues_past_drained_address(monkeypatch):
    """A nonce that was paid to but is now drained is not a gap.

    Scan must walk past drained nonces to reach later nonces that may
    hold fresh UTXOs. Treating "no current UTXOs" as a gap would
    truncate the scan whenever an earlier address had been fully spent.
    """
    from yubtc.wallet import Wallet
    from yubtc.crypto import seed2privkey, privkey2addr

    # The multi-form gap rule: a nonce is used when ANY form was ever
    # paid, so mark every form of nonces 0 (drained) and 1 (funded)
    # as used.
    stub_used_nonces(monkeypatch, [0, 1])
    # nonce 0 is used but drained, nonce 1 has UTXOs, nonce 2 is the true gap.
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({1: [60_000]}))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    sources, cashback_addr = w._scan_inputs(target=200_000, confirmations=0, on_address=None)

    # The drained nonce 0 contributes nothing; nonce 1 is the only source.
    assert len(sources) == 1
    assert sources[0][0].nonce == 1
    # True gap sits at nonce 2 -- cashback goes there (as `str`).
    gap_addr = privkey2addr(
        privkey=seed2privkey(seed='qwe', nonce=2, passphrase='')).decode('ascii')
    assert cashback_addr == gap_addr


def test_Wallet_make_transaction_scan_drains_past_drained_address(monkeypatch):
    """make_transaction's scan path also walks past drained addresses.

    The drained address contributes no inputs; later addresses are
    drained in full (amount=None).
    """
    from yubtc.wallet import Wallet

    # nonce 0 used-but-drained, nonce 1 holds the funds, nonce 2 is the gap.
    stub_used_nonces(monkeypatch, [0, 1])
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({1: [40_000]}))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=None, fee=1_000,
        feekb=2_000, confirmations=0, scan=True,
        sources=None, cashback_addr=None, on_address=None,
    )
    # One input from nonce 1; drained nonce 0 contributes nothing.
    assert len(result.tx.vin) == 1
    # amount=None drains everything collected.
    assert result.cashback == 0
    assert result.amount == 40_000 - result.fee


def test_Wallet_scan_inputs_invokes_on_address_for_each_source(monkeypatch):
    """on_address(tp, unspent) is called once per sourced address, not for the gap-limit stop."""
    from yubtc.wallet import Wallet
    # Nonces 0, 1 are used (P2PKH form holds the UTXOs); nonce 2 is the
    # gap -> stop. Only 0 and 1 should be reported via the callback.
    stub_used_nonces(monkeypatch, [0, 1])
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [60_000], 1: [60_000]}))

    seen = []
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    sources, _ = w._scan_inputs(
        target=200_000, confirmations=0,
        on_address=lambda tp, unspent: seen.append((tp.nonce, len(unspent))),
    )
    assert seen == [(0, 1), (1, 1)]
    assert len(sources) == 2


def test_Wallet_scan_inputs_on_address_runs_before_target_check(monkeypatch):
    """The callback fires for the address that satisfies the target, not just earlier ones."""
    from yubtc.wallet import Wallet
    stub_used_nonces(monkeypatch, [0, 1, 2])
    # Target met at nonce 1; callback should fire for both 0 and 1.
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [30_000], 1: [30_000], 2: [30_000]}))

    seen = []
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    w._scan_inputs(
        target=50_000, confirmations=0,
        on_address=lambda tp, unspent: seen.append(tp.nonce),
    )
    assert seen == [0, 1]


def test_Wallet_make_transaction_scan_change_goes_to_last_input(monkeypatch):
    """When scan halts at the target, change goes to the last input's address."""
    from yubtc.wallet import Wallet
    from yubtc.transaction import script2pkh
    from yubtc.base58check import base58CheckEncode
    stub_used_nonces(monkeypatch, [0, 1, 2])
    # Nonces 0, 1, 2 all have UTXOs. Target = amount + fee = 51_000 ->
    # stop after nonce 1 (total 60_000 >= 51_000).
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [30_000], 1: [30_000], 2: [30_000]}))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=1_000,
        feekb=2_000, confirmations=0, scan=True,
        sources=None, cashback_addr=None, on_address=None,
    )
    # Cashback > 0 -> first vout is the change output.
    assert result.cashback > 0
    change_addr = base58CheckEncode(b'\x00' + script2pkh(bytes(result.tx.vout[0].script))).decode('ascii')
    # The last input is at nonce 1 (the scan stopped at total >= 50_000).
    from yubtc.crypto import seed2privkey, privkey2addr
    last_input_addr = privkey2addr(
        privkey=seed2privkey(seed='qwe', nonce=1, passphrase='')).decode('ascii')
    assert change_addr == last_input_addr


def test_Wallet_make_transaction_scan_signs_with_privkey_per_input(monkeypatch):
    """Each input in a scanned tx is signed with its own privkey."""
    from yubtc.wallet import Wallet
    from yubtc.crypto import seed2privkey, privkey2pubkey
    stub_used_nonces(monkeypatch, [0, 1])
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [40_000], 1: [40_000]}))

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    result = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=1_000,
        feekb=2_000, confirmations=0, scan=True,
        sources=None, cashback_addr=None, on_address=None,
    )
    pubwif_0 = privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0, passphrase=''))
    pubwif_1 = privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=1, passphrase=''))
    scripts = [vin.script for vin in result.tx.vin]
    # The two input scripts end with distinct pubwifs.
    assert any(s.endswith(pubwif_0) for s in scripts)
    assert any(s.endswith(pubwif_1) for s in scripts)


def test_Wallet_make_transaction_raises_when_scan_missing(monkeypatch):
    """make_transaction requires `scan`."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    with pytest.raises(TypeError, match='scan not set'):
        w.make_transaction(
            dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=1_000,
            feekb=2_000, confirmations=0,
            sources=None, cashback_addr=None, on_address=None,
        )


def test_Wallet_send_scan_passes_scan_to_make_transaction(monkeypatch, monkeypatch_input):
    """Wallet.send wires scan=True through to make_transaction."""
    from yubtc.wallet import Wallet
    import yubtc.wallet as wallet_mod
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent',
                        fake_unspent_per_nonce({0: [60_000]}))
    sent = MagicMock()
    import yubtc.net
    monkeypatch.setattr(yubtc.net, 'broadcastTx', sent)

    captured = {}

    def wrapper(self, **kwargs):
        captured['scan'] = kwargs.get('scan')
        # Stub: just return a no-op signed tx so the rest of send runs.
        from yubtc.transaction import CIn, COut, CTransaction
        from yubtc.crypto import seed2privkey, privkey2pubkey
        privkey = seed2privkey(seed='qwe', nonce=0, passphrase='')
        pubwif = privkey2pubkey(privkey=privkey)
        tx = CTransaction(
            vin=[CIn(txhash=b'\xab' * 32, n=0, script=b'', sequence=0xffffffff)],
            vout=[COut(amount=10_000, script=b'\xac')],
            locktime=0,
        ).sign(signers=[(privkey, pubwif)])
        return TxResult(tx=tx, cashback=0, amount=10_000, fee=1_000)

    monkeypatch.setattr(wallet_mod.Wallet, 'make_transaction', wrapper)

    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    from decimal import Decimal
    w.send(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=Decimal('0.0001'),
           fee=Decimal('0.00001'), feekb=2_000, confirmations=0,
           broadcast=False, scan=True, on_address=None, yes=False)
    assert captured['scan'] is True


def test_Wallet_scan_inputs_raises_when_confirmations_missing(monkeypatch):
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', lambda backend, address, **kwargs: [])
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    with pytest.raises(TypeError, match='target not set'):
        w._scan_inputs(confirmations=0)


def test_Wallet_scan_inputs_rejects_positional_args(monkeypatch):
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.net.get_address_info',
                        lambda backend, address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.net.get_address_unspent', lambda backend, address, **kwargs: [])
    w = Wallet(seed='qwe', nonce=0, new_addresses=1, passphrase='', backend=_BACKEND)
    with pytest.raises(TypeError, match='only kwargs allowed'):
        w._scan_inputs(0)
