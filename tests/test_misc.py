"""Tests for misc.py: pure helpers and address unpacking.

Network wrappers (`get_address_unspent`, `get_address_info`) live in
`tests/test_net.py`.
"""
from decimal import Decimal

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
# TBTC: a Decimal subclass that converts parse errors to ValueError.
# ---------------------------------------------------------------------------

def test_TBTC_is_decimal_subclass():
    """TBTC is a Decimal -- arithmetic and Decimal interop work unchanged."""
    from yubtc.fwd import TBTC
    assert issubclass(TBTC, Decimal)
    assert TBTC('0.5') == Decimal('0.5')
    assert TBTC(0) * TBTC(2) == Decimal('0')
    # The (sign, digits, exp) tuple form used by satoshi2btc still works.
    assert TBTC((0, (1,), -8)) == Decimal('0.00000001')


@pytest.mark.parametrize('value', ['abc', '', '1.2.3', 'not-a-number'])
def test_TBTC_invalid_string_raises_value_error(value):
    """Unparseable input -> ValueError (not decimal.InvalidOperation).

    ValueError is the standard Python idiom for invalid input and click
    already wraps it in BadParameter, so the CLI shows a usable message.
    """
    from yubtc.fwd import TBTC
    with pytest.raises(ValueError, match='not a valid BTC amount'):
        TBTC(value)


def test_TBTC_invalid_value_error_is_catchable_as_value_error():
    """The error is a ValueError; callers don't need to import `decimal`."""
    import decimal
    from yubtc.fwd import TBTC
    raised = None
    try:
        TBTC('abc')
    except ValueError as e:
        raised = e
    assert raised is not None
    # InvalidOperation is a subclass of ArithmeticError, not ValueError.
    # Catchers that only know ValueError (the standard "bad input"
    # convention) don't accidentally trip on it.
    assert not isinstance(raised, decimal.InvalidOperation)


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
