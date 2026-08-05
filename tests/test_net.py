"""Tests for net.py: the wallet's network surface.

`get_address_unspent` and `get_address_info` hit blockchain.info via
`requests.get`. `broadcastTx` POSTs a signed raw tx to blockchain.info/pushtx.
All three are patched through `requests` so the suite stays offline.

One quirk surfaced during test design; the tests pin the current behaviour
rather than silently fixing it:
- `get_address_unspent` / `get_address_info` have no catch-all except for
  `JSONDecodeError`, so any other exception (e.g. a missing JSON key) is
  meant to propagate out unchanged.
- `broadcastTx` raises on non-2xx responses so the wallet sees the failure
  after it has already printed the tx id.
"""
from json.decoder import JSONDecodeError
from unittest.mock import MagicMock

import pytest

from yubtc.net import NetworkBackend


class OfflineBackend(NetworkBackend):
    def get_unspent(self, address, **kwargs):
        return []

    def get_info(self, address, **kwargs):
        return {'total_received': 0}

    def send_tx(self, rawtx, **kwargs):
        pass


# ---------------------------------------------------------------------------
# broadcastTx: POST the raw tx to blockchain.info/pushtx.
# ---------------------------------------------------------------------------

def test_broadcastTx_posts_raw_tx_as_form_field(monkeypatch):
    """The raw tx is hex-encoded and sent as a form-encoded `tx` field."""
    import requests
    fake = MagicMock()
    fake.ok = True
    fake.status_code = 200
    fake.text = 'Transaction Submitted'
    captured = []
    monkeypatch.setattr(requests, 'post',
                        lambda url, **kwargs: (captured.append((url, kwargs)), fake)[1])
    from yubtc.net import broadcastTx
    broadcastTx(b'\x00\x01\x02\xff')
    assert captured[0][0] == 'https://blockchain.info/pushtx'
    assert captured[0][1]['data'] == {'tx': '000102ff'}


def test_broadcastTx_passes_timeout(monkeypatch):
    """Same as the GET counterparts -- timeout is pinned on every call."""
    import requests
    fake = MagicMock()
    fake.ok = True
    fake.status_code = 200
    fake.text = 'Transaction Submitted'
    captured = []
    monkeypatch.setattr(requests, 'post',
                        lambda url, **kwargs: (captured.append(kwargs), fake)[1])
    from yubtc.net import broadcastTx
    broadcastTx(b'\x00')
    assert 'timeout' in captured[0]
    assert captured[0]['timeout'] > 0


def test_broadcastTx_raises_on_non_2xx(monkeypatch):
    """A non-2xx response surfaces as an exception so the wallet sees the failure."""
    import requests
    fake = MagicMock()
    fake.ok = False
    fake.status_code = 500
    fake.text = 'Internal Server Error'
    monkeypatch.setattr(requests, 'post', lambda url, **kwargs: fake)
    from yubtc.net import broadcastTx
    with pytest.raises(RuntimeError, match='broadcast failed'):
        broadcastTx(b'\x00')


# ---------------------------------------------------------------------------
# get_address_unspent / get_address_info: network wrappers.
#
# The mock operates on `requests.get` (the module attribute). The functions
# inside net.py do `import requests` lazily, but they look up `get` on the
# module object at call time, so patching the module attribute works.
# ---------------------------------------------------------------------------

def test_get_address_unspent_returns_unspent_outputs(monkeypatch):
    import requests
    fake = MagicMock()
    fake.json.return_value = {
        'unspent_outputs': [
            {'tx': 'aaa', 'out_n': 0, 'amount': 1000},
            {'tx': 'bbb', 'out_n': 1, 'amount': 2000},
        ],
    }
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.net import get_address_unspent
    out = get_address_unspent(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    assert out == [
        {'tx': 'aaa', 'out_n': 0, 'amount': 1000},
        {'tx': 'bbb', 'out_n': 1, 'amount': 2000},
    ]


def test_get_address_unspent_uses_unspent_endpoint(monkeypatch):
    """The query string encodes the address; assert the URL is well-formed."""
    import requests
    fake = MagicMock()
    fake.json.return_value = {'unspent_outputs': []}
    captured = []
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: (captured.append(url), fake)[1])
    from yubtc.net import get_address_unspent
    get_address_unspent(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    assert captured == ['https://blockchain.info/unspent?active=1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k']


def test_get_address_unspent_returns_empty_on_json_decode_error(monkeypatch):
    import requests
    fake = MagicMock()
    fake.json.side_effect = JSONDecodeError('msg', 'doc', 0)
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.net import get_address_unspent
    assert get_address_unspent(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k') == []


def test_get_address_unspent_propagates_non_json_errors(monkeypatch):
    """A KeyError is not JSONDecodeError, so it propagates out unchanged."""
    import requests
    fake = MagicMock()
    fake.json.return_value = {'wrong_key': []}  # KeyError when we look up 'unspent_outputs'
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.net import get_address_unspent
    with pytest.raises(KeyError):
        get_address_unspent(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')


def test_get_address_unspent_passes_timeout(monkeypatch):
    """The wallet pins a timeout on every requests.get so a hung server
    can't freeze the CLI indefinitely."""
    import requests
    fake = MagicMock()
    fake.json.return_value = {'unspent_outputs': []}
    captured = []
    monkeypatch.setattr(requests, 'get',
                        lambda url, **kwargs: (captured.append(kwargs), fake)[1])
    from yubtc.net import get_address_unspent
    get_address_unspent(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    assert 'timeout' in captured[0]
    assert captured[0]['timeout'] > 0


def test_get_address_info_returns_address_subdict(monkeypatch):
    import requests
    fake = MagicMock()
    info = {'total_received': 5000, 'final_balance': 3000, 'n_tx': 7}
    fake.json.return_value = {'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k': info}
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.net import get_address_info
    assert get_address_info(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k') == info


def test_get_address_info_uses_balance_endpoint(monkeypatch):
    import requests
    fake = MagicMock()
    fake.json.return_value = {'1addr': {'total_received': 0}}
    captured = []
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: (captured.append(url), fake)[1])
    from yubtc.net import get_address_info
    get_address_info(b'1addr')
    assert captured == ['https://blockchain.info/balance?active=1addr']


def test_get_address_info_returns_zero_received_on_json_decode_error(monkeypatch):
    import requests
    fake = MagicMock()
    fake.json.side_effect = JSONDecodeError('msg', 'doc', 0)
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.net import get_address_info
    assert get_address_info(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k') == {'total_received': 0}


def test_get_address_info_propagates_non_json_errors(monkeypatch):
    """A KeyError is not JSONDecodeError, so it propagates out unchanged."""
    import requests
    fake = MagicMock()
    fake.json.return_value = {'some_other_address': {'total_received': 0}}  # KeyError
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.net import get_address_info
    with pytest.raises(KeyError):
        get_address_info(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')


def test_get_address_info_passes_timeout(monkeypatch):
    """Same as the unspent counterpart -- timeout is pinned on every call."""
    import requests
    fake = MagicMock()
    fake.json.return_value = {'1addr': {'total_received': 0}}
    captured = []
    monkeypatch.setattr(requests, 'get',
                        lambda url, **kwargs: (captured.append(kwargs), fake)[1])
    from yubtc.net import get_address_info
    get_address_info(b'1addr')
    assert 'timeout' in captured[0]
    assert captured[0]['timeout'] > 0


# ---------------------------------------------------------------------------
# NetworkBackend abstraction.
#
# The wallet doesn't import blockchain.info directly; it talks to a
# `NetworkBackend` resolved at call time via `get_current_backend()`.
# `use_backend()` swaps the default for the process; `reset_backend()`
# restores the `BlockchainInfoBackend`.
# ---------------------------------------------------------------------------

def test_NetworkBackend_default_methods_raise():
    """The base class is abstract -- subclasses must override."""
    from yubtc.net import NetworkBackend
    b = NetworkBackend()
    with pytest.raises(NotImplementedError):
        b.get_unspent(b'addr')
    with pytest.raises(NotImplementedError):
        b.get_info(b'addr')
    with pytest.raises(NotImplementedError):
        b.send_tx(b'\x00')


def test_OfflineBackend_returns_empty_data_and_is_silent_broadcast():
    """`OfflineBackend` is the no-op backend: no UTXOs, fresh address, no broadcast."""
    b = OfflineBackend()
    assert b.get_unspent(b'addr') == []
    assert b.get_info(b'addr') == {'total_received': 0}
    # No exception means the broadcast was swallowed.
    b.send_tx(b'\x00')


def test_free_functions_delegate_to_current_backend():
    """Each free function resolves the current backend and calls its method.

    Swapping the backend via `set_current_backend` changes what the
    free functions return/raise, even though the functions themselves
    never reference blockchain.info.
    """
    from yubtc.net import (
        get_address_info, get_address_unspent, broadcastTx,
        set_current_backend, reset_backend,
    )

    class FakeBackend(NetworkBackend):
        def __init__(self):
            self.calls = []

        def get_unspent(self, address, **kwargs):
            self.calls.append(('unspent', address))
            return [{'marker': 'unspent'}]

        def get_info(self, address, **kwargs):
            self.calls.append(('info', address))
            return {'marker': 'info'}

        def send_tx(self, rawtx, **kwargs):
            self.calls.append(('send', rawtx))

    fake = FakeBackend()
    set_current_backend(fake)
    try:
        assert get_address_unspent(b'1addr') == [{'marker': 'unspent'}]
        assert get_address_info(b'1addr') == {'marker': 'info'}
        broadcastTx(b'\x01\x02')
        assert fake.calls == [
            ('unspent', b'1addr'),
            ('info', b'1addr'),
            ('send', b'\x01\x02'),
        ]
    finally:
        reset_backend()


def test_get_current_backend_default_is_blockchain_info_backend():
    """`get_current_backend()` returns a `BlockchainInfoBackend` by default."""
    from yubtc.net import BlockchainInfoBackend, get_current_backend
    assert isinstance(get_current_backend(), BlockchainInfoBackend)


def test_set_current_backend_swaps_current_backend():
    """`set_current_backend` swaps; `reset_backend` restores."""
    from yubtc.net import get_current_backend, reset_backend, set_current_backend
    fake = OfflineBackend()
    set_current_backend(fake)
    assert get_current_backend() is fake
    reset_backend()
    assert get_current_backend() is not fake


def test_set_current_backend_takes_effect_for_wallet_calls():
    """End-to-end: after `set_current_backend(OfflineBackend())`, wallet
    network calls go through the new backend (no exceptions, no real
    HTTP)."""
    from yubtc.net import reset_backend, set_current_backend
    from yubtc.wallet import TPrivKey
    set_current_backend(OfflineBackend())
    try:
        p = TPrivKey(seed='qwe', nonce=0, passphrase='')
        # OfflineBackend returns no UTXOs and a fresh address.
        assert p.get_unspent(confirmations=0) == []
        assert p.is_unused() is True
        assert p.get_info() == {'total_received': 0}
    finally:
        reset_backend()
