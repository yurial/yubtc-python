"""Tests for misc.py: pure helpers, address unpacking, and network wrappers.

The network wrappers (`get_address_unspent`, `get_address_info`) hit
blockchain.info. They are tested against `unittest.mock`-style fakes for
`requests.get` so the suite stays offline.

One bug surfaced during test design; the test pins the current behaviour
rather than silently fixing it:
- `get_address_unspent` / `get_address_info` have a trailing
  `raise Exception('Unknown error')` that is unreachable: any exception
  other than `JSONDecodeError` propagates past the try/except unchanged.
"""
from decimal import Decimal
from json.decoder import JSONDecodeError
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# varint: Bitcoin CompactSize encoding.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('n, expected', [
    (0, b'\x00'),
    (1, b'\x01'),
    (0xfc, b'\xfc'),
    # 0xfd prefix: 1 + 2 LE bytes. Boundary: 0xffff is NOT < 0xffff, so it
    # falls through to the 0xfe encoding.
    (0xfd, b'\xfd\xfd\x00'),
    (0xfffe, b'\xfd\xfe\xff'),
    # 0xfe prefix: 1 + 4 LE bytes.
    (0xffff, b'\xfe\xff\xff\x00\x00'),
    (0x10000, b'\xfe\x00\x00\x01\x00'),
    (0xfffffffe, b'\xfe\xfe\xff\xff\xff'),
    # 0xff prefix: 1 + 8 LE bytes.
    (0xffffffff, b'\xff\xff\xff\xff\xff\x00\x00\x00\x00'),
    (0x100000000, b'\xff\x00\x00\x00\x00\x01\x00\x00\x00'),
    (0xdeadbeef12345678, b'\xff\x78\x56\x34\x12\xef\xbe\xad\xde'),
])
def test_varint_known_answers(n, expected):
    from yubtc.misc import varint
    assert varint(n) == expected


# ---------------------------------------------------------------------------
# varstr: varint(len(s)) + s.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('s', [b'', b'a', b'abc', b'x' * 252, b'x' * 253, b'x' * 0xffff])
def test_varstr(s):
    from yubtc.misc import varstr, varint
    assert varstr(s) == varint(len(s)) + s


# ---------------------------------------------------------------------------
# satoshi2btc / btc2satoshi: unit conversions.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('sat, btc', [
    (0, Decimal('0')),
    (1, Decimal('0.00000001')),
    (100_000_000, Decimal('1')),
    (50_000_000, Decimal('0.5')),
    (1_234_567_89, Decimal('1.23456789')),
])
def test_satoshi2btc_known_values(sat, btc):
    from yubtc.misc import satoshi2btc
    assert satoshi2btc(sat) == btc


@pytest.mark.parametrize('btc, sat', [
    (Decimal('0'), 0),
    (Decimal('0.00000001'), 1),
    (Decimal('1'), 100_000_000),
    (Decimal('0.5'), 50_000_000),
    (Decimal('1.23456789'), 123_456_789),
])
def test_btc2satoshi_known_values(btc, sat):
    from yubtc.misc import btc2satoshi
    assert btc2satoshi(btc) == sat


@pytest.mark.parametrize('value', [0, 1, 1_000, 1_000_000, 21_000_000 * 100_000_000])
def test_satoshi_roundtrip(value):
    from yubtc.misc import satoshi2btc, btc2satoshi
    assert btc2satoshi(satoshi2btc(value)) == value


# ---------------------------------------------------------------------------
# unpack_address: returns (prefix, dsthash) for a base58check address.
# ---------------------------------------------------------------------------

def test_unpack_address_p2pkh():
    from yubtc.misc import unpack_address
    prefix, dsthash = unpack_address(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    assert prefix == 0
    assert len(dsthash) == 20
    assert dsthash.hex() == 'e96b5b4561e70170c16f51ca30a9429e3bede977'


def test_unpack_address_p2sh():
    from yubtc.misc import unpack_address
    prefix, dsthash = unpack_address(b'3HLj8ECNk9A7Mbk8LegGS4i5EDNxfdCDn4')
    assert prefix == 5
    assert len(dsthash) == 20


def test_unpack_address_invalid_checksum_raises():
    from yubtc.misc import unpack_address
    # Mutate the last char (the checksum) -- base58check must reject it.
    with pytest.raises(Exception):
        unpack_address(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7l')


# ---------------------------------------------------------------------------
# yesno: interactive y/n prompt. Reads from `misc.raw_input`, which is
# assigned to the builtin `input` at module import time. Patching the
# module attribute is the cleanest seam -- no need to touch builtins.
# ---------------------------------------------------------------------------

def test_yesno_accepts_yes(monkeypatch):
    import yubtc.misc as misc
    monkeypatch.setattr(misc, 'raw_input', lambda _: 'yes')
    from yubtc.misc import yesno
    assert yesno('?') is True


def test_yesno_accepts_no(monkeypatch):
    import yubtc.misc as misc
    monkeypatch.setattr(misc, 'raw_input', lambda _: 'no')
    from yubtc.misc import yesno
    assert yesno('?') is False


def test_yesno_case_insensitive(monkeypatch):
    import yubtc.misc as misc
    monkeypatch.setattr(misc, 'raw_input', lambda _: 'Y')
    from yubtc.misc import yesno
    assert yesno('?') is True
    monkeypatch.setattr(misc, 'raw_input', lambda _: 'N')
    assert yesno('?') is False


def test_yesno_loops_until_valid(monkeypatch):
    import yubtc.misc as misc
    responses = iter(['maybe', '', 'what?', 'y'])
    monkeypatch.setattr(misc, 'raw_input', lambda _: next(responses))
    from yubtc.misc import yesno
    assert yesno('?') is True


def test_yesno_short_circuits_on_yes_or_no_prefix(monkeypatch):
    """'yodel' and 'nowhere' both pass -- the check is on the first character."""
    import yubtc.misc as misc
    monkeypatch.setattr(misc, 'raw_input', lambda _: 'yodel')
    from yubtc.misc import yesno
    assert yesno('?') is True
    monkeypatch.setattr(misc, 'raw_input', lambda _: 'nowhere')
    assert yesno('?') is False


# ---------------------------------------------------------------------------
# get_address_unspent / get_address_info: network wrappers.
#
# The mock operates on `requests.get` (the module attribute). The functions
# inside misc.py do `import requests` lazily, but they look up `get` on the
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
    from yubtc.misc import get_address_unspent
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
    from yubtc.misc import get_address_unspent
    get_address_unspent(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    assert captured == ['https://blockchain.info/unspent?active=1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k']


def test_get_address_unspent_returns_empty_on_json_decode_error(monkeypatch):
    import requests
    fake = MagicMock()
    fake.json.side_effect = JSONDecodeError('msg', 'doc', 0)
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.misc import get_address_unspent
    assert get_address_unspent(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k') == []


def test_get_address_unspent_propagates_non_json_errors(monkeypatch):
    """A KeyError is not JSONDecodeError, so it propagates out unchanged."""
    import requests
    fake = MagicMock()
    fake.json.return_value = {'wrong_key': []}  # KeyError when we look up 'unspent_outputs'
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.misc import get_address_unspent
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
    from yubtc.misc import get_address_unspent
    get_address_unspent(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')
    assert 'timeout' in captured[0]
    assert captured[0]['timeout'] > 0


def test_get_address_info_returns_address_subdict(monkeypatch):
    import requests
    fake = MagicMock()
    info = {'total_received': 5000, 'final_balance': 3000, 'n_tx': 7}
    fake.json.return_value = {'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k': info}
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.misc import get_address_info
    assert get_address_info(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k') == info


def test_get_address_info_uses_balance_endpoint(monkeypatch):
    import requests
    fake = MagicMock()
    fake.json.return_value = {'1addr': {'total_received': 0}}
    captured = []
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: (captured.append(url), fake)[1])
    from yubtc.misc import get_address_info
    get_address_info(b'1addr')
    assert captured == ['https://blockchain.info/balance?active=1addr']


def test_get_address_info_returns_zero_received_on_json_decode_error(monkeypatch):
    import requests
    fake = MagicMock()
    fake.json.side_effect = JSONDecodeError('msg', 'doc', 0)
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.misc import get_address_info
    assert get_address_info(b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k') == {'total_received': 0}


def test_get_address_info_propagates_non_json_errors(monkeypatch):
    """A KeyError is not JSONDecodeError, so it propagates out unchanged."""
    import requests
    fake = MagicMock()
    fake.json.return_value = {'some_other_address': {'total_received': 0}}  # KeyError
    monkeypatch.setattr(requests, 'get', lambda url, **kwargs: fake)
    from yubtc.misc import get_address_info
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
    from yubtc.misc import get_address_info
    get_address_info(b'1addr')
    assert 'timeout' in captured[0]
    assert captured[0]['timeout'] > 0
