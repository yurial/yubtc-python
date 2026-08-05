"""Tests for net.py: the wallet's network surface.

Three functions live here:
- `sendTx` is a stub (raises NotImplementedError). The tests pin that
  behaviour so a future implementation has to actively change them.
- `get_address_unspent` and `get_address_info` hit blockchain.info via
  `requests.get`. Tests patch `requests.get` so the suite stays offline.

One quirk surfaced during test design; the tests pin the current behaviour
rather than silently fixing it:
- `get_address_unspent` / `get_address_info` have no catch-all except for
  `JSONDecodeError`, so any other exception (e.g. a missing JSON key) is
  meant to propagate out unchanged.
"""
from json.decoder import JSONDecodeError
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# sendTx: stub for broadcasting transactions.
# ---------------------------------------------------------------------------

def test_sendTx_is_a_stub():
    """sendTx raises NotImplementedError on any call."""
    from yubtc.net import sendTx
    with pytest.raises(NotImplementedError):
        sendTx(b'\x00' * 100)


def test_sendTx_does_not_touch_the_network():
    """The stub must not import or use requests -- it has no network call."""
    # If this import succeeded before the test, the next assertion is meaningful.
    import yubtc.net as net
    assert not hasattr(net, 'requests')


def test_sendTx_message_mentions_block_explorer():
    """The error message tells the user how to actually broadcast."""
    from yubtc.net import sendTx
    with pytest.raises(NotImplementedError) as info:
        sendTx(b'\x00')
    assert 'block explorer' in str(info.value).lower()


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
