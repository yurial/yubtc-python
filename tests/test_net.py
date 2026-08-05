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


# ---------------------------------------------------------------------------
# BlockchainInfoBackend with a custom base URL.
#
# The base URL is the only constructor knob; it lets a corporate
# firewall's mirror serve the same endpoints without code changes.
# ---------------------------------------------------------------------------

def test_blockchain_info_backend_with_custom_base_url(monkeypatch):
    """`BlockchainInfoBackend(base_url=...)` retargets every endpoint."""
    import requests

    # Three captures for the three endpoints (unspent, balance, pushtx).
    get_captured = []
    post_captured = []

    def fake_get(url, **kwargs):
        get_captured.append(url)
        fake = MagicMock()
        if 'unspent' in url:
            fake.json.return_value = {'unspent_outputs': []}
        else:
            fake.json.return_value = {'addr': {'total_received': 0}}
        return fake

    def fake_post(url, **kwargs):
        post_captured.append(url)
        fake = MagicMock()
        fake.ok = True
        fake.status_code = 200
        fake.text = 'Transaction Submitted'
        return fake

    monkeypatch.setattr(requests, 'get', fake_get)
    monkeypatch.setattr(requests, 'post', fake_post)

    from yubtc.net import BlockchainInfoBackend
    b = BlockchainInfoBackend(base_url='https://mirror.example.com')
    b.get_unspent(b'addr')
    b.get_info(b'addr')
    b.send_tx(b'\x00\x01')

    # Every endpoint got the mirror base, not blockchain.info.
    assert get_captured == [
        'https://mirror.example.com/unspent?active=addr',
        'https://mirror.example.com/balance?active=addr',
    ]
    assert post_captured == ['https://mirror.example.com/pushtx']


# ---------------------------------------------------------------------------
# EsploraBackend: shared blockstream / mempool.space parent.
#
# The two concrete providers differ only in base URL; their tests cover
# the same logic but against different URLs. The parent class is also
# exercised directly via a custom base URL so the URL-formatting logic
# is reachable without subclassing.
# ---------------------------------------------------------------------------

def _stub_esplora(monkeypatch, *, utxos, tip_height, address_stats):
    """Patch requests.get to serve the three Esplora endpoints.

    `utxos`: the JSON the /address/<addr>/utxo endpoint returns.
    `tip_height`: the int the /blocks/tip/height endpoint returns.
    `address_stats`: the JSON the /address/<addr> endpoint returns.

    Returns a list that captures every (url, kwargs) pair in call order
    so tests can assert on call sequencing.
    """
    import requests

    captured = []

    def fake_get(url, **kwargs):
        captured.append((url, kwargs))
        fake = MagicMock()
        if url.endswith('/utxo'):
            fake.json.return_value = utxos
        elif url.endswith('/blocks/tip/height'):
            fake.text = str(tip_height)
        else:
            # Plain /address/<addr> returns the chain/mempool stats dict.
            fake.json.return_value = address_stats
        return fake

    monkeypatch.setattr(requests, 'get', fake_get)
    return captured


def test_esplora_get_unspent_translates_utxo_shape(monkeypatch):
    """Esplora `{txid, vout, value, status}` -> wallet
    `{tx_hash, tx_output_n, value, script, confirmations}`."""
    from yubtc.net import EsploraBackend

    utxos = [
        {'txid': 'aa' * 32, 'vout': 0, 'value': 100_000,
         'status': {'confirmed': True, 'block_height': 90}},
    ]
    captured = _stub_esplora(
        monkeypatch, utxos=utxos, tip_height=100,
        address_stats={'chain_stats': {}, 'mempool_stats': {}},
    )

    addr = b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
    b = EsploraBackend(base_url='https://blockstream.info/api')
    out = b.get_unspent(addr)

    # The wallet-shaped entry: confirmations = tip - block_height + 1.
    expected_script = EsploraBackend._lock_script(addr)
    assert out == [{
        'tx_hash': 'aa' * 32,
        'tx_output_n': 0,
        'value': 100_000,
        'script': expected_script.hex(),
        'confirmations': 11,
    }]

    # The UTXO endpoint fires first; the tip is consulted exactly once.
    assert captured[0][0] == 'https://blockstream.info/api/address/1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k/utxo'
    assert captured[1][0] == 'https://blockstream.info/api/blocks/tip/height'
    assert len(captured) == 2


def test_esplora_get_unspent_returns_empty_without_tip_lookup(monkeypatch):
    """An empty UTXO list short-circuits: no tip call, no script."""
    from yubtc.net import EsploraBackend

    captured = _stub_esplora(
        monkeypatch, utxos=[], tip_height=100,
        address_stats={'chain_stats': {}, 'mempool_stats': {}},
    )

    addr = b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
    b = EsploraBackend(base_url='https://blockstream.info/api')
    assert b.get_unspent(addr) == []

    # Only the UTXO endpoint was hit; the tip is not needed.
    assert len(captured) == 1
    assert captured[0][0].endswith('/address/1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k/utxo')


def test_esplora_get_unspent_unconfirmed_utxo_has_zero_confirmations(monkeypatch):
    """Mempool entries (confirmed=False) report 0 confirmations."""
    from yubtc.net import EsploraBackend

    utxos = [
        {'txid': 'aa' * 32, 'vout': 0, 'value': 100,
         'status': {'confirmed': False}},
    ]
    _stub_esplora(
        monkeypatch, utxos=utxos, tip_height=999,
        address_stats={'chain_stats': {}, 'mempool_stats': {}},
    )

    addr = b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
    b = EsploraBackend(base_url='https://blockstream.info/api')
    out = b.get_unspent(addr)
    assert out[0]['confirmations'] == 0


def test_esplora_get_unspent_reconstructs_p2pkh_script_from_address(monkeypatch):
    """The UTXO endpoint omits the script; the backend rebuilds it
    from the queried address so the wallet's input builder can use it."""
    from yubtc.net import EsploraBackend

    utxos = [
        {'txid': 'aa' * 32, 'vout': 0, 'value': 1,
         'status': {'confirmed': True, 'block_height': 1}},
    ]
    _stub_esplora(
        monkeypatch, utxos=utxos, tip_height=1,
        address_stats={'chain_stats': {}, 'mempool_stats': {}},
    )

    addr = b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
    b = EsploraBackend(base_url='https://blockstream.info/api')
    out = b.get_unspent(addr)
    # P2PKH script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    expected_script = EsploraBackend._lock_script(addr)
    assert out[0]['script'] == expected_script.hex()


def test_esplora_get_info_translates_chain_and_mempool_stats(monkeypatch):
    """`total_received` is the sum of chain + mempool funded sums."""
    from yubtc.net import EsploraBackend

    _stub_esplora(
        monkeypatch, utxos=[], tip_height=0,
        address_stats={
            'chain_stats': {
                'funded_txo_sum': 1_000,
                'spent_txo_sum': 400,
                'tx_count': 5,
            },
            'mempool_stats': {
                'funded_txo_sum': 200,
                'spent_txo_sum': 50,
                'tx_count': 2,
            },
        },
    )

    addr = b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
    b = EsploraBackend(base_url='https://blockstream.info/api')
    info = b.get_info(addr)
    assert info['total_received'] == 1_200
    assert info['final_balance'] == 750  # 1_200 - 400 - 50
    assert info['n_tx'] == 7


def test_esplora_get_info_handles_missing_keys(monkeypatch):
    """An Esplora response with no chain_stats/mempool_stats returns zeros.

    Some implementations return an empty `{}` for a never-used address;
    the `.get() or {}` chain in the backend makes that a zero-everywhere
    response, not a `KeyError`.
    """
    from yubtc.net import EsploraBackend

    _stub_esplora(
        monkeypatch, utxos=[], tip_height=0,
        address_stats={},
    )

    addr = b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
    b = EsploraBackend(base_url='https://blockstream.info/api')
    info = b.get_info(addr)
    assert info == {'total_received': 0, 'final_balance': 0, 'n_tx': 0}


def test_esplora_send_tx_posts_raw_hex_to_tx_endpoint(monkeypatch):
    """`send_tx` POSTs the hex-encoded rawtx to `/tx`, no form wrapping."""
    import requests
    from yubtc.net import EsploraBackend

    captured = []
    fake = MagicMock()
    fake.ok = True
    fake.status_code = 200
    fake.text = 'txid'
    monkeypatch.setattr(requests, 'post',
                        lambda url, **kwargs: (captured.append((url, kwargs)), fake)[1])

    b = EsploraBackend(base_url='https://blockstream.info/api')
    b.send_tx(b'\x00\x01\x02\xff')
    assert captured[0][0] == 'https://blockstream.info/api/tx'
    # Raw hex in the body, no `data` dict wrapping.
    assert captured[0][1]['data'] == '000102ff'


def test_esplora_send_tx_raises_on_non_2xx(monkeypatch):
    """A non-2xx response surfaces as RuntimeError so the wallet sees the failure."""
    import requests
    from yubtc.net import EsploraBackend

    fake = MagicMock()
    fake.ok = False
    fake.status_code = 400
    fake.text = 'bad tx'
    monkeypatch.setattr(requests, 'post', lambda url, **kwargs: fake)

    b = EsploraBackend(base_url='https://blockstream.info/api')
    with pytest.raises(RuntimeError, match='broadcast failed'):
        b.send_tx(b'\x00')


# ---------------------------------------------------------------------------
# BlockstreamBackend / MempoolSpaceBackend: thin subclasses with the right URL.
# ---------------------------------------------------------------------------

def test_blockstream_backend_uses_blockstream_base_url(monkeypatch):
    """`BlockstreamBackend()` is an `EsploraBackend` pinned to blockstream.info."""
    from yubtc.net import BlockstreamBackend, EsploraBackend
    b = BlockstreamBackend()
    assert isinstance(b, EsploraBackend)
    assert b._base_url == 'https://blockstream.info/api'


def test_mempool_space_backend_uses_mempool_base_url():
    """`MempoolSpaceBackend()` is an `EsploraBackend` pinned to mempool.space."""
    from yubtc.net import EsploraBackend, MempoolSpaceBackend
    b = MempoolSpaceBackend()
    assert isinstance(b, EsploraBackend)
    assert b._base_url == 'https://mempool.space/api'


def test_blockstream_backend_get_unspent_hits_blockstream_urls(monkeypatch):
    """End-to-end: a BlockstreamBackend issues requests to blockstream.info."""
    from yubtc.net import BlockstreamBackend

    captured = _stub_esplora(
        monkeypatch, utxos=[], tip_height=100,
        address_stats={'chain_stats': {}, 'mempool_stats': {}},
    )
    BlockstreamBackend().get_unspent(b'1addr')
    assert captured[0][0] == 'https://blockstream.info/api/address/1addr/utxo'
    # Tip lookup was skipped because the UTXO list was empty.
    assert all('blockstream.info/api' in u for u, _ in captured)


def test_mempool_space_backend_get_unspent_hits_mempool_urls(monkeypatch):
    """End-to-end: a MempoolSpaceBackend issues requests to mempool.space."""
    from yubtc.net import MempoolSpaceBackend

    captured = _stub_esplora(
        monkeypatch, utxos=[], tip_height=100,
        address_stats={'chain_stats': {}, 'mempool_stats': {}},
    )
    MempoolSpaceBackend().get_unspent(b'1addr')
    assert captured[0][0] == 'https://mempool.space/api/address/1addr/utxo'
    assert all('mempool.space/api' in u for u, _ in captured)


def test_blockstream_backend_send_tx_posts_to_blockstream(monkeypatch):
    """send_tx targets the blockstream `/tx` endpoint."""
    import requests
    from yubtc.net import BlockstreamBackend

    captured = []
    fake = MagicMock()
    fake.ok = True
    fake.status_code = 200
    monkeypatch.setattr(requests, 'post',
                        lambda url, **kwargs: (captured.append(url), fake)[1])
    BlockstreamBackend().send_tx(b'\x00')
    assert captured == ['https://blockstream.info/api/tx']


def test_mempool_space_backend_send_tx_posts_to_mempool(monkeypatch):
    """send_tx targets the mempool.space `/tx` endpoint."""
    import requests
    from yubtc.net import MempoolSpaceBackend

    captured = []
    fake = MagicMock()
    fake.ok = True
    fake.status_code = 200
    monkeypatch.setattr(requests, 'post',
                        lambda url, **kwargs: (captured.append(url), fake)[1])
    MempoolSpaceBackend().send_tx(b'\x00')
    assert captured == ['https://mempool.space/api/tx']


# ---------------------------------------------------------------------------
# BACKENDS registry + get_backend factory.
#
# The CLI's --provider flag drives `get_backend(name=...)`. The
# registry must (a) list every supported provider and (b) raise on
# unknown names so a typo doesn't silently fall back.
# ---------------------------------------------------------------------------

def test_BACKENDS_lists_all_three_providers():
    """The registry exposes the three providers the wallet supports."""
    from yubtc.net import (
        BACKENDS, BlockchainInfoBackend, BlockstreamBackend, MempoolSpaceBackend,
    )
    assert set(BACKENDS) == {'blockchain.info', 'blockstream', 'mempool.space'}
    assert BACKENDS['blockchain.info'] is BlockchainInfoBackend
    assert BACKENDS['blockstream'] is BlockstreamBackend
    assert BACKENDS['mempool.space'] is MempoolSpaceBackend


def test_get_backend_default_is_blockchain_info():
    """`get_backend()` without a name returns the default provider."""
    from yubtc.net import BlockchainInfoBackend, get_backend
    assert isinstance(get_backend(), BlockchainInfoBackend)


def test_get_backend_by_name_returns_correct_class():
    """Each registered name resolves to its corresponding backend class."""
    from yubtc.net import (
        BlockchainInfoBackend, BlockstreamBackend, MempoolSpaceBackend, get_backend,
    )
    assert isinstance(get_backend(name='blockchain.info'), BlockchainInfoBackend)
    assert isinstance(get_backend(name='blockstream'), BlockstreamBackend)
    assert isinstance(get_backend(name='mempool.space'), MempoolSpaceBackend)


def test_get_backend_returns_fresh_instance_each_call():
    """Each call returns a new instance so callers don't share state."""
    from yubtc.net import get_backend
    a = get_backend(name='blockstream')
    b = get_backend(name='blockstream')
    assert a is not b


def test_get_backend_unknown_name_raises_value_error():
    """An unknown name surfaces as ValueError naming the registered providers."""
    from yubtc.net import get_backend
    with pytest.raises(ValueError) as ei:
        get_backend(name='not-a-real-provider')
    msg = str(ei.value)
    assert 'not-a-real-provider' in msg
    assert 'blockchain.info' in msg
    assert 'blockstream' in msg
    assert 'mempool.space' in msg
