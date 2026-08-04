"""Tests for wallet.py: TPrivKey and Wallet.

These pin the wallet's contract: how kwargs are validated, how the
seed-scan loop in `Wallet.__init__` walks nonces, how get_info caches,
how get_unspent filters by confirmations, and how the send/make_transaction
flow assembles a signed tx from one or more UTXOs.

The blockchain.info calls are stubbed per-test via `monkeypatch`.
"""
import pytest
from decimal import Decimal
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# TPrivKey: kwargs-only construction.
# ---------------------------------------------------------------------------

def test_TPrivKey_rejects_positional_args():
    """`TPrivKey(arg)` is invalid -- only kwargs are accepted."""
    from yubtc.wallet import TPrivKey
    with pytest.raises(Exception, match='only kwargs allowed'):
        TPrivKey('positional')


def test_TPrivKey_passes_through_known_privkey():
    """`privkey=...` is used directly; no derivation happens."""
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    p = TPrivKey(privkey=privkey, compressed=True)
    assert p.privkey == privkey
    assert p.nonce is None  # not set when constructed from raw privkey


def test_TPrivKey_derives_privkey_from_seed_and_nonce():
    """`seed=...` + `nonce=...` -> privkey via seed2privkey."""
    from coincurve import PrivateKey
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey
    p = TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.privkey == seed2privkey(seed='qwe', nonce=0)
    assert p.nonce == 0


def test_TPrivKey_requires_seed():
    """No privkey and no seed -> exception."""
    from yubtc.wallet import TPrivKey
    with pytest.raises(Exception, match='seed not set'):
        TPrivKey(nonce=0)


def test_TPrivKey_rejects_empty_seed():
    """An empty seed string is rejected -- it's distinct from "not set"."""
    from yubtc.wallet import TPrivKey
    with pytest.raises(Exception, match='seed cannot be empty'):
        TPrivKey(seed='', nonce=0, compressed=True)


def test_TPrivKey_requires_nonce():
    """seed but no nonce -> exception."""
    from yubtc.wallet import TPrivKey
    with pytest.raises(Exception, match='nonce not set'):
        TPrivKey(seed='qwe')


def test_TPrivKey_raises_when_compressed_missing():
    """`compressed` is required for both the privkey and seed paths."""
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    with pytest.raises(Exception, match='compressed not set'):
        TPrivKey(privkey=privkey)
    with pytest.raises(Exception, match='compressed not set'):
        TPrivKey(privkey=privkey, compressed=None)
    with pytest.raises(Exception, match='compressed not set'):
        TPrivKey(seed='qwe', nonce=0)
    with pytest.raises(Exception, match='compressed not set'):
        TPrivKey(seed='qwe', nonce=0, compressed=None)


# ---------------------------------------------------------------------------
# TPrivKey: derived helpers.
# ---------------------------------------------------------------------------

def test_TPrivKey_get_privwif_returns_compressed_wif_by_default():
    """Default is compressed (Bitcoin convention)."""
    from coincurve import PrivateKey
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey, privkey2privwif
    p = TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.get_privwif() == privkey2privwif(
        privkey=seed2privkey(seed='qwe', nonce=0), compressed=True,
    )


def test_TPrivKey_get_privwif_uncompressed():
    """compressed=False expands to the uncompressed WIF."""
    from coincurve import PrivateKey
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey, privkey2privwif
    p = TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.get_privwif(False) == privkey2privwif(
        privkey=seed2privkey(seed='qwe', nonce=0), compressed=False,
    )


def test_TPrivKey_get_p2pkh_address():
    """Address derivation reuses privkey2addr."""
    from coincurve import PrivateKey
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey, privkey2addr
    p = TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.get_p2pkh_address() == privkey2addr(
        privkey=seed2privkey(seed='qwe', nonce=0), compressed=True,
    )


def test_TPrivKey_get_p2pkh_address_with_explicit_compressed(monkeypatch):
    """Explicit `compressed=False` flows through without hitting the default."""
    from coincurve import PrivateKey
    from yubtc.wallet import TPrivKey
    from yubtc.crypto import seed2privkey, privkey2addr
    p = TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.get_p2pkh_address(False) == privkey2addr(
        privkey=seed2privkey(seed='qwe', nonce=0), compressed=False,
    )
    assert p.get_p2pkh_address(None) == privkey2addr(
        privkey=seed2privkey(seed='qwe', nonce=0), compressed=True,
    )


# ---------------------------------------------------------------------------
# TPrivKey.get_info: caches the network call.
# ---------------------------------------------------------------------------

def test_TPrivKey_get_info_caches(monkeypatch):
    """get_info calls the network once and caches the result in `_info`."""
    from yubtc.wallet import TPrivKey
    calls = []

    def fake_info(address):
        calls.append(address)
        return {'total_received': 0, 'final_balance': 0, 'n_tx': 0}
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_info', fake_info)

    p = TPrivKey(seed='qwe', nonce=0, compressed=True)
    a = p.get_info()
    b = p.get_info()
    assert a is b
    assert len(calls) == 1


def test_TPrivKey_get_info_returns_cached_dict(monkeypatch):
    """The cached dict is returned, not re-fetched."""
    from yubtc.wallet import TPrivKey
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 1, 'n_tx': 1})
    p = TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.get_info() == {'total_received': 1, 'n_tx': 1}


# ---------------------------------------------------------------------------
# TPrivKey.is_unused: total_received == 0
# ---------------------------------------------------------------------------

def test_TPrivKey_is_unused_when_total_received_is_zero(monkeypatch):
    import yubtc.wallet
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.is_unused() is True


def test_TPrivKey_is_used_when_total_received_is_nonzero(monkeypatch):
    import yubtc.wallet
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 1, 'n_tx': 1})
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.is_unused() is False


# ---------------------------------------------------------------------------
# TPrivKey.get_unspent: filters by confirmations and renames the API fields.
# ---------------------------------------------------------------------------

def test_TPrivKey_get_unspent_returns_empty_when_no_utxos(monkeypatch):
    import yubtc.wallet
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', lambda address, **kwargs: [])
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert p.get_unspent(confirmations=0) == []


def test_TPrivKey_get_unspent_renames_api_fields(monkeypatch):
    """The blockchain.info format uses tx_hash / tx_output_n / value / script.
    The wallet's internal format renames these to tx / out_n / amount / script."""
    import yubtc.wallet
    import yubtc.misc
    raw = [{'tx_hash': 'a' * 64, 'tx_output_n': 0, 'value': 50_000,
            'confirmations': 10, 'script': '76a914' + 'aa' * 20 + '88ac'}, ]
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', lambda address, **kwargs: raw)
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, compressed=True)
    out = p.get_unspent(confirmations=0)
    assert out == [
        {'tx': 'a' * 64, 'out_n': 0, 'amount': 50_000, 'script': '76a914' + 'aa' * 20 + '88ac'},
    ]


def test_TPrivKey_get_unspent_filters_low_confirmation_utxos(monkeypatch):
    import yubtc.wallet
    import yubtc.misc
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
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', lambda address, **kwargs: raw)
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, compressed=True)
    out = p.get_unspent(confirmations=5)
    assert len(out) == 1
    assert out[0]['tx'] == 'b' * 64


def test_TPrivKey_get_unspent_includes_equal_confirmation(monkeypatch):
    """Boundary: confirmations >= threshold (inclusive)."""
    import yubtc.wallet
    import yubtc.misc
    raw = [{'tx_hash': 'a' * 64, 'tx_output_n': 0, 'value': 50_000,
            'confirmations': 5, 'script': '76a914' + 'aa' * 20 + '88ac'}, ]
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', lambda address, **kwargs: raw)
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, compressed=True)
    assert len(p.get_unspent(confirmations=5)) == 1


def test_TPrivKey_get_unspent_raises_when_confirmations_missing():
    """get_unspent's `confirmations` is required -- callers must pass it."""
    import yubtc.wallet
    p = yubtc.wallet.TPrivKey(seed='qwe', nonce=0, compressed=True)
    with pytest.raises(Exception, match='confirmations not set'):
        p.get_unspent()
    with pytest.raises(Exception, match='confirmations not set'):
        p.get_unspent(confirmations=None)


# ---------------------------------------------------------------------------
# Wallet: kwargs-only construction.
# ---------------------------------------------------------------------------

def test_Wallet_rejects_positional_args():
    from yubtc.wallet import Wallet
    with pytest.raises(Exception, match='only kwargs allowed'):
        Wallet('positional')


def test_Wallet_from_privkey_creates_single_privkey(monkeypatch):
    """privkey=... -> a Wallet with one TPrivKey (no seed-scan)."""
    from yubtc.wallet import Wallet
    from coincurve import PrivateKey
    from yubtc.crypto import seed2privkey
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    w = Wallet(privkey=seed2privkey(seed='qwe', nonce=0), compressed=True, new_addresses=1)
    assert len(w.privkeys) == 1
    assert w.privkeys[0].privkey == seed2privkey(seed='qwe', nonce=0)


def test_Wallet_from_privwif_creates_single_privkey(monkeypatch):
    """privwif=... -> Wallet with one TPrivKey whose privkey matches the WIF."""
    from yubtc.wallet import Wallet
    from yubtc.crypto import privkey2privwif, seed2privkey
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    privkey = seed2privkey(seed='qwe', nonce=0)
    wif = privkey2privwif(privkey=privkey, compressed=True)
    w = Wallet(privwif=wif, compressed=True, new_addresses=1)
    assert len(w.privkeys) == 1
    assert w.privkeys[0].privkey == privkey


def test_Wallet_with_no_source_leaves_privkeys_unset(monkeypatch):
    """Wallet() with no privkey/privwif/seed: privkeys is left as None.

    This is the uncovered branch in Wallet.__init__: when no source is
    provided, the constructor falls through and never builds the privkey
    list, leaving the attribute at the placeholder None.
    """
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    w = Wallet()
    assert w.privkeys is None


def test_Wallet_send_rejects_positional_args(monkeypatch):
    """send(arg, ...) is invalid -- only kwargs are accepted."""
    from yubtc.wallet import Wallet
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    with pytest.raises(Exception, match='only kwargs allowed'):
        w.send('positional')


def test_Wallet_from_seed_stops_at_first_unused_address(monkeypatch):
    """The seed-scan loop terminates when an unused address is found."""
    from yubtc.wallet import Wallet
    # Address at nonce 0 is "used" (received funds); nonce 1 is fresh.
    counters = {'n': 0}

    def fake_info(address):
        counters['n'] += 1
        used = {'total_received': 1, 'n_tx': 1}
        fresh = {'total_received': 0, 'n_tx': 0}
        return used if counters['n'] == 1 else fresh
    monkeypatch.setattr('yubtc.misc.get_address_info', fake_info)
    monkeypatch.setattr('yubtc.misc.get_address_unspent', lambda address, **kwargs: [])

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    # Walked over nonce 0 (used), then nonce 1 (fresh) -> stop.
    assert len(w.privkeys) == 2
    assert w.privkeys[0].nonce == 0
    assert w.privkeys[1].nonce == 1


def test_Wallet_init_with_explicit_compressed(monkeypatch):
    """Explicit `compressed=True/False` flows through without hitting the default body."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', lambda address, **kwargs: [])
    # compressed=True and compressed=False both go through, no default applied.
    for c in (True, False):
        w = Wallet(seed='qwe', nonce=0, compressed=c, new_addresses=1)
        assert len(w.privkeys) == 1


def test_Wallet_from_seed_with_new_addresses(monkeypatch):
    """`new_addresses=N` follows the seed scan with N additional fresh addresses.

    The scan walks past any used addresses and breaks at the first unused one.
    Then `new_addresses` fresh addresses are appended starting from that nonce.
    """
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', lambda address, **kwargs: [])

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=3)
    # Nonce 0 is the first unused (no scan); then 3 fresh addresses appended.
    assert len(w.privkeys) == 3
    assert [p.nonce for p in w.privkeys] == [0, 1, 2]


def test_Wallet_from_seed_scan_then_appends(monkeypatch):
    """Scanned used addresses plus new_addresses fresh ones."""
    from yubtc.wallet import Wallet
    counters = {'n': 0}

    def fake_info(address):
        counters['n'] += 1
        return {'total_received': 1, 'n_tx': 1} if counters['n'] <= 2 else {'total_received': 0, 'n_tx': 0}
    monkeypatch.setattr('yubtc.misc.get_address_info', fake_info)
    monkeypatch.setattr('yubtc.misc.get_address_unspent', lambda address, **kwargs: [])

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=2)
    # Nonces 0,1 used (appended); nonce 2 is the first fresh (dropped); then
    # `new_addresses=2` more appended starting at nonce 2.
    assert len(w.privkeys) == 4
    assert [p.nonce for p in w.privkeys] == [0, 1, 2, 3]


# ---------------------------------------------------------------------------
# Wallet.send: builds a tx, asks yes/no, prints or sends.
# ---------------------------------------------------------------------------

def test_Wallet_send_dry_run_prints_raw_tx(monkeypatch, monkeypatch_input):
    """With send=False the raw tx hex is printed; sendTx is not called."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo())

    sent = MagicMock()
    import yubtc.net
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    out = dry_run_send(w, monkeypatch_input, dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount='0.0005')
    assert out is not None  # the tx was printed
    sent.assert_not_called()


def test_Wallet_send_with_amount_none_skips_btc2satoshi(monkeypatch, monkeypatch_input):
    """When amount=None, the wallet doesn't call btc2satoshi on it.

    Exercises the `if amount is not None:` short-circuit in Wallet.send.
    """
    from yubtc.wallet import Wallet
    import yubtc.misc
    import yubtc.net
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', fake_unspent_with_one_utxo())
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    out = dry_run_send(w, monkeypatch_input, dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=None)
    assert out is not None  # drained all funds; tx still printed
    sent.assert_not_called()


def test_Wallet_send_with_broadcast_calls_sendTx(monkeypatch, monkeypatch_input):
    """With send=True, the tx is passed to net.sendTx."""
    from yubtc.wallet import Wallet
    import yubtc.net
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo())

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    dry_run_send(w, monkeypatch_input, dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount='0.0005', send=True)
    sent.assert_called_once()


def test_Wallet_send_declined_prints_nothing(monkeypatch):
    """User answering 'n' to the confirmation prompt -> no tx, no send."""
    from yubtc.wallet import Wallet
    import yubtc.misc
    import yubtc.net

    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', fake_unspent_with_one_utxo())
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)

    # monkeypatch the yes/no prompt to decline.
    monkeypatch.setattr(yubtc.misc, 'yesno', lambda q: False)

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    from decimal import Decimal
    w.send(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=Decimal('0.0005'),
           fee=Decimal('0.00001'), feekb=2_000, confirmations=0, send=False)
    sent.assert_not_called()


def test_Wallet_send_raises_when_required_arg_missing(monkeypatch, monkeypatch_input):
    """Wallet.send raises when a required kwarg is omitted (None == not passed).

    `amount` is the exception: it stays None to mean "drain all available funds".
    """
    from yubtc.wallet import Wallet
    import yubtc.misc
    import yubtc.net
    monkeypatch.setattr(yubtc.misc, 'get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr(yubtc.misc, 'get_address_unspent', fake_unspent_with_one_utxo())
    sent = MagicMock()
    monkeypatch.setattr(yubtc.net, 'sendTx', sent)

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    base = dict(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k',
                amount=None, fee=Decimal('0.00001'), feekb=2_000,
                confirmations=0, send=False)
    with pytest.raises(Exception, match='dst not set'):
        w.send(**{**base, 'dst': None})
    with pytest.raises(Exception, match='fee not set'):
        w.send(**{**base, 'fee': None})
    with pytest.raises(Exception, match='feekb not set'):
        w.send(**{**base, 'feekb': None})
    with pytest.raises(Exception, match='confirmations not set'):
        w.send(**{**base, 'confirmations': None})
    with pytest.raises(Exception, match='send not set'):
        w.send(**{**base, 'send': None})


def test_Wallet_init_raises_when_compressed_or_new_addresses_missing(monkeypatch):
    """Wallet.__init__ requires `compressed` and `new_addresses`; None raises."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', lambda address, **kwargs: [])
    with pytest.raises(Exception, match='compressed not set'):
        Wallet(seed='qwe', nonce=0)
    with pytest.raises(Exception, match='new_addresses not set'):
        Wallet(seed='qwe', nonce=0, compressed=True)
    # privkey= path also requires `compressed`.
    from yubtc.crypto import seed2privkey
    privkey = seed2privkey(seed='qwe', nonce=0)
    with pytest.raises(Exception, match='compressed not set'):
        Wallet(privkey=privkey)
    with pytest.raises(Exception, match='compressed not set'):
        Wallet(privkey=privkey, compressed=None)


def test_Wallet_rejects_empty_seed(monkeypatch):
    """Empty seed string is rejected (distinct from "not set")."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', lambda address, **kwargs: [])
    with pytest.raises(Exception, match='seed cannot be empty'):
        Wallet(seed='', nonce=0, compressed=True, new_addresses=1)


# ---------------------------------------------------------------------------
# Wallet._make_vin: builds inputs from UTXOs.
# ---------------------------------------------------------------------------

def test_Wallet_make_vin_builds_cin_for_each_utxo(monkeypatch):
    """Each unspent UTXO becomes a CIn with the right txhash, n, and script."""
    from coincurve import PrivateKey
    from yubtc.wallet import Wallet
    from coincurve import PrivateKey
    from yubtc.crypto import seed2privkey, pubkey2pubwif, privkey2pubkey
    from yubtc.hash import hash160
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_two_utxos())

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    pubkey = privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0))
    pubwif = pubkey2pubwif(pubkey=pubkey, compressed=True)
    pubhash = hash160(pubwif)
    vin, in_amount = w._make_vin(pubhash=pubhash, unspent=w.privkeys[0].get_unspent(confirmations=0))
    assert in_amount == 100_000
    assert len(vin) == 2
    assert vin[0].txhash == b'\xaa' * 32
    assert vin[0].n == 0
    assert vin[1].txhash == b'\xbb' * 32
    assert vin[1].n == 1


def test_Wallet_make_vin_rejects_utxo_with_mismatched_pubkey(monkeypatch):
    """A UTXO whose lock script doesn't match our pubkey hash is rejected."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo())

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    with pytest.raises(Exception, match='unknown pubkey required'):
        # Pass a fake pubhash that doesn't match the UTXO's lock script.
        w._make_vin(pubhash=b'\x00' * 20, unspent=w.privkeys[0].get_unspent(confirmations=0))


# ---------------------------------------------------------------------------
# Wallet.make_transaction: builds and signs a tx.
# ---------------------------------------------------------------------------

def test_Wallet_make_transaction_drains_input_when_amount_is_none(monkeypatch):
    """amount=None -> no change output; all funds go to the destination."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo(amount=100_000))

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    stx, cashback, amount, fee = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=None, fee=1_000,
        feekb=2000, confirmations=0,
    )
    assert cashback == 0
    assert amount == 99_000
    assert len(stx.vout) == 1
    assert stx.vout[0].amount == 99_000


def test_Wallet_make_transaction_drains_when_amount_plus_fee_equals_input(monkeypatch):
    """Explicit drain: amount + fee == in_amount."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo(amount=100_000))

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    stx, cashback, amount, fee = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=99_000, fee=1_000,
        feekb=2000, confirmations=0,
    )
    assert cashback == 0
    assert len(stx.vout) == 1


def test_Wallet_make_transaction_adds_change_output(monkeypatch):
    """amount + fee < in_amount -> a change output back to the source."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo(amount=100_000))

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    stx, cashback, amount, fee = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=1_000,
        feekb=2000, confirmations=0,
    )
    assert cashback == 49_000
    assert amount == 50_000
    assert len(stx.vout) == 2
    # Output order: change first, then payment.
    assert stx.vout[0].amount == 49_000
    assert stx.vout[1].amount == 50_000


def test_Wallet_make_transaction_signs_with_owners_privkey(monkeypatch):
    """The signed tx's input scripts use the wallet's owner privkey."""
    from yubtc.wallet import Wallet
    from coincurve import PrivateKey
    from yubtc.crypto import seed2privkey, pubkey2pubwif, privkey2pubkey
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo(amount=100_000))

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    stx, _, _, _ = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=1_000,
        feekb=2000, confirmations=0,
    )
    pubwif = pubkey2pubwif(
        pubkey=privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0)),
        compressed=True,
    )
    # The signed signature script ends with the pubwif.
    assert stx.vin[0].script.endswith(pubwif)


def test_Wallet_make_transaction_recurses_until_fee_is_stable(monkeypatch):
    """When fee is not provided, the loop iterates until the fee rate is stable."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo(amount=200_000))

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    # Use feekb so the fee is set iteratively; no fixed fee.
    stx, cashback, amount, fee = w.make_transaction(
        dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000, fee=0, feekb=2000,
        confirmations=0,
    )
    # txsize is small enough that the second iteration converges.
    assert fee > 0
    # The cashback + amount + fee equals the in_amount.
    assert cashback + amount + fee == 200_000


def test_Wallet_make_transaction_raises_when_confirmations_or_feekb_missing(monkeypatch):
    """make_transaction requires `confirmations` and `feekb`; `fee` may be None."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo())

    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    base = dict(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000,
                fee=1_000, feekb=2_000, confirmations=0)
    with pytest.raises(Exception, match='confirmations not set'):
        w.make_transaction(**{**base, 'confirmations': None})
    with pytest.raises(Exception, match='feekb not set'):
        w.make_transaction(**{**base, 'feekb': None})


def test_Wallet_make_transaction_raises_when_dst_missing(monkeypatch):
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    base = dict(dst='1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', amount=50_000,
                fee=1_000, feekb=2_000, confirmations=0)
    with pytest.raises(Exception, match='dst not set'):
        w.make_transaction(**{**base, 'dst': None})


def test_Wallet_make_vin_raises_when_pubhash_or_unspent_missing(monkeypatch):
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    with pytest.raises(Exception, match='pubhash not set'):
        w._make_vin(unspent=[])
    with pytest.raises(Exception, match='unspent not set'):
        w._make_vin(pubhash=b'\x00' * 20)


def test_Wallet_methods_reject_positional_args(monkeypatch):
    """send / make_transaction / _make_vin all require kwargs-only calls."""
    from yubtc.wallet import Wallet
    monkeypatch.setattr('yubtc.misc.get_address_info',
                        lambda address: {'total_received': 0, 'n_tx': 0})
    monkeypatch.setattr('yubtc.misc.get_address_unspent', fake_unspent_with_one_utxo())
    w = Wallet(seed='qwe', nonce=0, compressed=True, new_addresses=1)
    # send: positional dst is no longer allowed -- 'only kwargs allowed'.
    with pytest.raises(Exception, match='only kwargs allowed'):
        w.send('1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    # make_transaction: same.
    with pytest.raises(Exception, match='only kwargs allowed'):
        w.make_transaction('1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k', 50_000)
    # _make_vin: same.
    with pytest.raises(Exception, match='only kwargs allowed'):
        w._make_vin(b'\x00' * 20, [])


# ---------------------------------------------------------------------------
# Helpers (test-local).
# ---------------------------------------------------------------------------

@pytest.fixture
def monkeypatch_input(monkeypatch):
    """Patch `yubtc.misc.yesno` to confirm everything."""
    import yubtc.misc
    monkeypatch.setattr(yubtc.misc, 'yesno', lambda q: True)


def dry_run_send(w, input_fixture, dst, amount, send=False):
    """Run wallet.send with the local yes/no fixture and capture stdout.

    `amount` is in BTC (the wallet's TBTC units). It is converted to a Decimal
    so btc2satoshi treats it as BTC, not satoshi. Pass amount=None to send all.
    """
    from decimal import Decimal
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    btc_amount = Decimal(amount) if amount is not None else None
    with redirect_stdout(buf):
        w.send(dst=dst, amount=btc_amount, fee=Decimal('0.00001'), feekb=2_000,
               confirmations=0, send=send)
    out = buf.getvalue()
    # The hex is the second line after `id: <txid>`.
    if send:
        return None  # broadcast path doesn't print the hex
    return out


def fake_unspent_with_one_utxo(amount=100_000):
    """A one-UTXO unspent list whose lock script matches the qwe seed."""
    from coincurve import PrivateKey
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    from yubtc.hash import hash160
    pubwif = pubkey2pubwif(
        pubkey=privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0)),
        compressed=True,
    )
    pubhash = hash160(pubwif)
    # P2PKH lock script: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
    script = '76a914' + pubhash.hex() + '88ac'
    raw = [
        {'tx_hash': 'a' * 64, 'tx_output_n': 0, 'value': amount, 'confirmations': 10, 'script': script},
    ]
    return lambda address, **kwargs: raw


def fake_unspent_with_two_utxos():
    """Two UTXOs for the same address."""
    from coincurve import PrivateKey
    from yubtc.crypto import seed2privkey, privkey2pubkey, pubkey2pubwif
    from yubtc.hash import hash160
    pubwif = pubkey2pubwif(
        pubkey=privkey2pubkey(privkey=seed2privkey(seed='qwe', nonce=0)),
        compressed=True,
    )
    pubhash = hash160(pubwif)
    script = '76a914' + pubhash.hex() + '88ac'
    raw = [
        {'tx_hash': 'aa' * 32, 'tx_output_n': 0, 'value': 50_000, 'confirmations': 10, 'script': script},
        {'tx_hash': 'bb' * 32, 'tx_output_n': 1, 'value': 50_000, 'confirmations': 10, 'script': script},
    ]
    return lambda address, **kwargs: raw
