"""Tests for script.py: the CScript class.

The bulk of script.py is a list of opcode constants; that's a static
declaration, not behaviour. The only branchy code is `CScript.__new__`,
which has to coerce each element of an iterable into bytes.

These tests cover the three missing branches:
- `bytes`/`bytearray` passed directly to `CScript(...)`.
- A bytes element longer than 0x4b (the inline-pushdata limit).
- A non-CScriptOp / non-bytes element (e.g. an int or a str).
"""
import pytest

from yubtc.script import (
    CScript, OP_0, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL,
)


# ---------------------------------------------------------------------------
# CScript(bytes) -- the bytes/bytearray branch of __new__.
# ---------------------------------------------------------------------------

def test_cscript_from_bytes_passes_through():
    """bytes argument is stored verbatim (no PUSHDATA prefix)."""
    out = CScript(b'\x76\xa9')
    assert bytes(out) == b'\x76\xa9'
    assert isinstance(out, CScript)


def test_cscript_from_bytearray_passes_through():
    """bytearray is converted to bytes then stored."""
    out = CScript(bytearray(b'\x76\xa9'))
    assert bytes(out) == b'\x76\xa9'
    assert isinstance(out, CScript)


def test_cscript_default_construction_raises():
    """`CScript()` with no argument raises -- callers must pass a value."""
    with pytest.raises(Exception, match='value not set'):
        CScript()
    with pytest.raises(Exception, match='value not set'):
        CScript(None)


# ---------------------------------------------------------------------------
# CScript from iterable: CScriptOp + bytes inline PUSHDATA.
# ---------------------------------------------------------------------------

def test_cscript_from_iterable_mixes_opcodes_and_bytes():
    """Each element is encoded by its coercion rule."""
    out = CScript([OP_DUP, b'\xaa' * 20, OP_CHECKSIG])
    assert bytes(out) == b'\x76\x14' + b'\xaa' * 20 + b'\xac'


def test_cscript_from_iterable_accepts_bytearray():
    """bytearray elements are coerced just like bytes."""
    out = CScript([OP_DUP, bytearray(b'\xbb' * 20), OP_CHECKSIG])
    assert bytes(out) == b'\x76\x14' + b'\xbb' * 20 + b'\xac'


# ---------------------------------------------------------------------------
# Error paths.
# ---------------------------------------------------------------------------

def test_cscript_rejects_pushdata_too_long_for_inline_encoding():
    """A bytes element with len >= 0x4c cannot use the inline encoding."""
    with pytest.raises(ValueError):
        CScript([OP_0, b'\x00' * 0x4c])
    with pytest.raises(ValueError):
        CScript([OP_0, b'\x00' * 1000])


def test_cscript_rejects_unsupported_element_type():
    """Anything that isn't CScriptOp or bytes/bytearray raises TypeError."""
    with pytest.raises(TypeError):
        CScript([OP_0, 5])             # int
    with pytest.raises(TypeError):
        CScript([OP_0, 'hello'])       # str
    with pytest.raises(TypeError):
        CScript([OP_0, None])          # None


# ---------------------------------------------------------------------------
# Sanity: the standard P2PKH/P2SH scripts the wallet actually builds.
# ---------------------------------------------------------------------------

def test_p2pkh_script_byte_layout():
    """P2PKH: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG."""
    dst = b'\xaa' * 20
    out = CScript([OP_DUP, OP_HASH160, dst, OP_EQUALVERIFY, OP_CHECKSIG])
    assert bytes(out) == b'\x76\xa9\x14' + dst + b'\x88\xac'


def test_p2sh_script_byte_layout():
    """P2SH: OP_HASH160 <20B> OP_EQUAL."""
    dst = b'\xab' * 20
    out = CScript([OP_HASH160, dst, OP_EQUAL])
    assert bytes(out) == b'\xa9\x14' + dst + b'\x87'


# ---------------------------------------------------------------------------
# CScriptOp: a thin int subclass.
# ---------------------------------------------------------------------------

def test_cscriptop_is_an_int_with_one_byte_value():
    """Each opcode is just an int in [0, 0xff]."""
    assert int(OP_DUP) == 0x76
    assert int(OP_HASH160) == 0xa9
    assert int(OP_CHECKSIG) == 0xac
    assert int(OP_EQUAL) == 0x87
    assert int(OP_EQUALVERIFY) == 0x88
