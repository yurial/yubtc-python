"""PSBT -- Partially Signed Bitcoin Transaction (BIP-174, Phase 14 v0.2).

Pure-stdlib mirror of `yubtc core/src/psbt.rs` (the bit-for-bit oracle):
a transport container for exchanging partial signatures between a
stateless yubtc wallet and external coordinators. Everything that
eventually goes on-chain is byte-for-byte identical to the Phase 13
flows (`yubtc.transaction`); this module adds only the container, the
canonical (de)serialization, and the five BIP-174 roles (Creator,
Signer, Combiner, Finalizer, Extractor) plus a human-readable `decode`
summary (`psbt_summary`).

Wire format (BIP-174)::

    <psbt>    := 0x70 0x73 0x62 0x74 0xFF <global-map> <input-map>* <output-map>*
    <map>     := <keypair>* 0x00
    <keypair> := <keylen><keytype><keydata><valuelen><valuedata>

Contract highlights (all tested, spec.md «Сериализация»):

- **Canonical ordering** -- the serializer emits each map's pairs in
  ascending full-key-byte order (type, then keydata, lexicographic),
  giving bit-for-bit determinism against the Rust port. The parser
  accepts any order.
- **Duplicates** -- a repeated full key inside one map is
  `DuplicateKey` (a PSBT with duplicates is invalid per BIP-174).
- **Minimal key types** -- the `<keytype>` prefix must be a
  minimally-encoded compact size (`0xFD 0x00 0x02` for type 2 is
  `NonMinimalCompactSize`).
- **Exact keydata lengths** -- "no key data" field types require
  ``keylen == 1``; pubkey-keyed fields (`PARTIAL_SIG`, BIP-32
  derivation) require a 33-byte compressed or 65-byte uncompressed
  pubkey (other lengths -> `InvalidKeyLength`).
- **Size guard** -- inputs above `yubtc.fwd.PSBT_MAX_SIZE` fail with
  `TooLarge` before any allocation (fuzz/OOM guard).
- **Unknown-field passthrough** -- fields outside the in-scope set
  (xpubs, BIP-32 derivations, preimage fields, BIP-371 taproot fields,
  proprietary ``0xFC``, anything unassigned) are kept as opaque
  `(key, value)` byte pairs and carried through the whole pipeline
  byte-for-byte; the extracted transaction never sees them.
- **Map counts** -- the number of input/output maps must equal the
  unsigned tx's input/output counts (`MapCountMismatch`).

Signing is restricted to P2PKH / P2WPKH / P2TR key-path /
P2SH-multisig (Phase 15 -- via a canonical `REDEEM_SCRIPT`:
membership signing with `scriptCode = redeem`, the
`OP_0 ‖ sigs ‖ redeem` finalize layout) / P2WSH-multisig (v0.3 --
via a canonical `WITNESS_SCRIPT` membership, BIP-143 with
`scriptCode = redeem`, the `[dummy, sigs..., redeem]` witness
layout) and reuses the Phase 13
primitives (`bip143_sighash`, `taproot_keypath_sighash`,
`taproot_sign_sighash`, RFC6979 ECDSA, Schnorr with
``aux_rand = 0x00 * 32``); signatures match the direct `sign_segwit`
path byte-for-byte. P2WSH without a witness script and redeem-less
P2SH inputs answer `UnsupportedInputScript`.
"""
from struct import pack, unpack
from typing import NamedTuple, Optional

from yubtc.fwd import (PSBT_MAX_SIZE, PSBT_SIGN_MAX_NONCE,
                       PSBT_SIGHASH_ALL, PSBT_SIGHASH_DEFAULT)
from yubtc.util import NotNone, require_kwargs_only
from yubtc.transaction import (compact_size, dsha256, p2wpkh_script_code,
                               bip143_sighash, taproot_keypath_sighash,
                               taproot_sign_sighash)

# --- Errors (mirrors the 18 PsbtError variants of psbt.rs) ------------


class PsbtError(Exception):
    """Everything that can go wrong in a PSBT's life.

    Base class of the 18 typed variants mirroring the Rust
    `PsbtError` enum one-for-one; every variant is a tested branch.
    The messages are the Rust `thiserror` strings, one-for-one."""

    #: The message a payload-less variant carries (mirrors the Rust
    #: `#[error("...")]` attribute).
    default_message = 'PSBT error'

    def __init__(self, *args):
        if not args:
            args = (self.default_message,)
        super().__init__(*args)


class InvalidMagic(PsbtError):
    """The bytes do not start with the `psbt` magic ``0x70 0x73 0x62
    0x74 0xFF`` -- e.g. a raw network transaction was passed instead
    of a PSBT (official BIP-174 invalid vector)."""

    default_message = 'not a PSBT: bad magic bytes'


class Truncated(PsbtError):
    """The byte stream ended in the middle of a keypair, a value, or
    before an expected map terminator; also a second map terminator
    (a stray ``0x00``) and key-type prefixes shorter than their
    declared width."""

    default_message = 'PSBT data truncated or structurally malformed'


class NonMinimalCompactSize(PsbtError):
    """The field-type prefix of a key was not minimally encoded as a
    compact size (e.g. ``0xFD 0x00 0x02`` for type 2)."""

    default_message = 'key type compact size is not minimally encoded'


class InvalidKeyLength(PsbtError):
    """The key data length does not match the field type: a "no key
    data" field carried keydata, or a pubkey-keyed field carried a key
    that is neither 33 nor 65 bytes. Carries the offending field type."""

    @require_kwargs_only
    def __init__(self, field_type: int = NotNone):
        super().__init__(
            f'invalid key data length for field type {field_type}')
        self.field_type = field_type


class DuplicateKey(PsbtError):
    """The same full key appeared twice in one map. BIP-174: a PSBT
    with duplicate keys is invalid."""

    default_message = 'duplicate key in a PSBT map'


class UnsupportedVersion(PsbtError):
    """The global `VERSION` field carried a value other than 0. PSBTv2
    (BIP-370) is an explicit non-goal for Phase 14."""

    @require_kwargs_only
    def __init__(self, version: int = NotNone):
        super().__init__(
            f'unsupported PSBT version {version} (only v0 is supported)')
        self.version = version


class MissingUnsignedTx(PsbtError):
    """The global map has no `UNSIGNED_TX` field (v0 mandate)."""

    default_message = 'global map lacks the UNSIGNED_TX field'


class InvalidUnsignedTx(PsbtError):
    """The `UNSIGNED_TX` value did not parse as a valid unsigned
    transaction: malformed wire bytes, zero outputs, a non-empty
    `scriptSig`, or witness serialization format."""

    default_message = 'UNSIGNED_TX is not a valid unsigned transaction'


class MapCountMismatch(PsbtError):
    """The number of input or output maps differs from the unsigned
    transaction's input or output count (including maps missing at
    end-of-data or extra maps after the expected ones)."""

    default_message = ('input/output map count does not match the '
                       'unsigned transaction')


class InvalidFieldValue(PsbtError):
    """A typed field's value was malformed: wrong length (VERSION,
    SIGHASH_TYPE), trailing bytes after a UTXO structure, or an
    invalid base64 transport encoding."""

    default_message = 'field value malformed'


class UnsupportedInputScript(PsbtError):
    """The input's UTXO `scriptPubKey` needs redeem/witness script
    support yubtc refuses: a P2WSH shape, or a P2SH input whose
    `REDEEM_SCRIPT` is absent or not a canonical bare CHECKMULTISIG
    script (Phase 15: with a canonical redeem script a P2SH-multisig
    input is signed, finalized and extracted; P2WSH and redeem-less
    P2SH stay preserve-only)."""

    default_message = ('input script requires redeem/witness script '
                       'support (P2SH/P2WSH)')


class UtxoMismatch(PsbtError):
    """The `NON_WITNESS_UTXO` of an input being signed does not hash
    to the referenced prevout txid. No signature is produced (BIP-174
    "Data Signers Check For")."""

    default_message = ('NON_WITNESS_UTXO does not hash to the referenced '
                       'prevout txid')


class UnsupportedSighashType(PsbtError):
    """The input carries a `SIGHASH_TYPE` that differs from the sighash
    pinned for its form (`SIGHASH_ALL` for P2PKH/P2WPKH,
    `SIGHASH_DEFAULT` for P2TR key-path -- ОВ-8). The wallet-level
    Signer walk treats this as "leave unsigned"; the library
    primitive reports it."""

    @require_kwargs_only
    def __init__(self, sighash_type: int = NotNone):
        super().__init__(
            f'SIGHASH_TYPE {sighash_type} does not match the sighash '
            'pinned for this input form')
        self.sighash_type = sighash_type


class ConflictingField(PsbtError):
    """`combine` found the same key with different values. yubtc fails
    deterministically instead of picking arbitrarily (spec: KAT
    reproducibility; commutativity on disjoint signers is preserved)."""

    default_message = 'combine conflict: same key with different values'


class ForeignTransaction(PsbtError):
    """`combine` was called on PSBTs whose global `UNSIGNED_TX` values
    differ (byte comparison) -- they are not the same transaction."""

    default_message = 'combine refused: UNSIGNED_TX values differ'


class IncompleteInput(PsbtError):
    """An input lacks the data the requested per-input operation
    needs: no UTXO field to finalize against, no matching partial
    signature, a blocked sighash byte, or an unknown script form.
    Carries the input index."""

    @require_kwargs_only
    def __init__(self, index: int = NotNone):
        super().__init__(f'input {index} is incomplete for the requested '
                         'operation')
        self.index = index


class NotFinalized(PsbtError):
    """`extract_transaction` refused: at least one input has no
    completed final fields (or a form that cannot be validated).
    The PSBT is not modified (BIP-174 Extractor MUST)."""

    default_message = 'not all inputs are finalized; extraction refused'


class TooLarge(PsbtError):
    """The encoded PSBT exceeds `yubtc.fwd.PSBT_MAX_SIZE` (4 MiB) --
    rejected before any allocation."""

    default_message = (f'PSBT exceeds the {PSBT_MAX_SIZE}-byte size cap')


# --- Field type constants (BIP-174 registry) --------------------------
#
# Global `UNSIGNED_TX` (0x00); per-input `NON_WITNESS_UTXO` (0x00);
# per-output `REDEEM_SCRIPT` (0x00). Global `XPUB` (0x01);
# per-input `WITNESS_UTXO` (0x01); per-output `WITNESS_SCRIPT` (0x01).
# Per-input `PARTIAL_SIG` (0x02); per-output `BIP32_DERIVATION` (0x02).
T_UNSIGNED_TX = 0x00
T_GLOBAL_XPUB = 0x01
T_IN_WITNESS_UTXO = 0x01
T_PARTIAL_SIG = 0x02
T_SIGHASH_TYPE = 0x03
T_REDEEM_SCRIPT = 0x04
T_WITNESS_SCRIPT = 0x05
T_IN_BIP32_DERIVATION = 0x06
T_FINAL_SCRIPTSIG = 0x07
T_FINAL_SCRIPTWITNESS = 0x08
T_VERSION = 0xFB

MAGIC = b'\x70\x73\x62\x74\xff'

# Valid keydata lengths for pubkey-keyed fields: compressed and
# uncompressed SEC pubkeys.
_PUBKEY_KEY_LENGTHS = (33, 65)


# --- Wire primitives ---------------------------------------------------


class _Reader(object):
    """Sequential reader over a PSBT byte slice. All reads are
    bounds-checked; any over-read is `Truncated` -- there are no
    panics and no oversized allocations (values are slices into the
    input, never copied up-front)."""

    def __init__(self, data: bytes):
        self.data = bytes(data)
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def at_end(self) -> bool:
        return self.pos >= len(self.data)

    def peek(self, offset: int) -> Optional[int]:
        pos = self.pos + offset
        if pos >= len(self.data):
            return None
        return self.data[pos]

    def take(self, n: int) -> bytes:
        if n > self.remaining():
            raise Truncated()
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def read_array(self, n: int) -> bytes:
        return self.take(n)

    def read_compact_size(self) -> int:
        """Bitcoin CompactSize. Encoding-strictness is deliberately
        relaxed here (only the *key type* prefix must be minimal per
        spec); the 4 MiB cap plus slice-based reads make oversized
        lengths a plain truncation, not an allocation bomb."""
        prefix = self.read_array(1)[0]
        if prefix <= 0xfc:
            return prefix
        if prefix == 0xfd:
            return unpack('<H', self.read_array(2))[0]
        if prefix == 0xfe:
            return unpack('<L', self.read_array(4))[0]
        return unpack('<Q', self.read_array(8))[0]


def _write_compact_size(out: bytearray, n: int) -> None:
    """Append the CompactSize encoding of `n` to `out`."""
    if n < 0xfd:
        out += pack('<B', n)
    elif n <= 0xffff:
        out += pack('<cH', b'\xfd', n)
    elif n <= 0xffffffff:
        out += pack('<cL', b'\xfe', n)
    else:
        out += pack('<cQ', b'\xff', n)


def _split_key(key: bytes) -> tuple:
    """Split a PSBT key into ``(field type, keydata)``. The type prefix
    must be a minimally-encoded CompactSize (`NonMinimalCompactSize`
    otherwise); a truncated prefix is `Truncated`."""
    if not key:
        raise Truncated()
    prefix = key[0]
    if prefix <= 0xfc:
        return prefix, key[1:]
    if prefix == 0xfd:
        if len(key) < 3:
            raise Truncated()
        v = unpack('<H', key[1:3])[0]
        if v < 0xfd:
            raise NonMinimalCompactSize()
        return v, key[3:]
    if prefix == 0xfe:
        if len(key) < 5:
            raise Truncated()
        v = unpack('<L', key[1:5])[0]
        if v <= 0xffff:
            raise NonMinimalCompactSize()
        return v, key[5:]
    if len(key) < 9:
        raise Truncated()
    v = unpack('<Q', key[1:9])[0]
    if v <= 0xffffffff:
        raise NonMinimalCompactSize()
    return v, key[9:]


def _pubkey_keydata_len(keydata: bytes) -> bool:
    """Keydata length check for pubkey-keyed fields (`PARTIAL_SIG`,
    BIP-32 derivation): exactly 33 or 65 bytes."""
    return len(keydata) in _PUBKEY_KEY_LENGTHS


def _read_map(r: _Reader) -> list:
    """Read one key/value map; the zero-length key terminates it.
    Duplicate full keys are `DuplicateKey` (BIP-174: "Handling
    Duplicated Keys" -- a PSBT with duplicates is invalid)."""
    out = []
    seen = set()
    while True:
        if r.at_end():
            raise Truncated()
        keylen = r.read_compact_size()
        if keylen == 0:
            return out
        key = r.take(keylen)
        if key in seen:
            raise DuplicateKey()
        seen.add(key)
        valuelen = r.read_compact_size()
        value = r.take(valuelen)
        out.append((key, value))


def _write_map(out: bytearray, pairs: list) -> None:
    """Emit one map: pairs sorted by full key bytes, then the
    terminator. Keys are unique within a map (parse rejects duplicates;
    the creators below build unique keys), so the order is total and
    the canonical form deterministic."""
    for key, value in sorted(pairs, key=lambda kv: kv[0]):
        _write_compact_size(out, len(key))
        out += key
        _write_compact_size(out, len(value))
        out += value
    out.append(0)


# --- Transaction model (values of UNSIGNED_TX / NON_WITNESS_UTXO) -----
#
# The Rust oracle parses into its `Transaction`/`TxIn`/`TxOut` structs;
# the Python mirror uses value-comparable NamedTuples so tests can
# assert structural equality (the wallet's `CTransaction` hardcodes
# version 2 and would not round-trip the version-1 prev transactions
# of the official BIP-174 vectors).


class PsbtTxIn(NamedTuple):
    """One transaction input (mirrors the Rust `TxIn`). `witness` is a
    tuple of stack items (empty for stripped layouts)."""
    txhash: bytes
    n: int
    script: bytes
    sequence: int
    witness: tuple

    def serialize(self) -> bytes:
        result = self.txhash
        result += pack('<L', self.n)
        result += compact_size(len(self.script))
        result += self.script
        result += pack('<L', self.sequence)
        return result


class PsbtTxOut(NamedTuple):
    """One transaction output (mirrors the Rust `TxOut`)."""
    amount: int
    script: bytes

    def serialize(self) -> bytes:
        result = pack('<Q', self.amount)
        result += compact_size(len(self.script))
        result += self.script
        return result


class PsbtTransaction(NamedTuple):
    """A parsed or constructed transaction (mirrors the Rust
    `Transaction`): version is a free signed int32 -- the unsigned-tx
    container must round-trip coordinator-supplied versions (the
    official BIP-174 prev transactions are version 1)."""
    version: int
    vin: tuple
    vout: tuple
    locktime: int

    def serialize_stripped(self) -> bytes:
        """The pre-SegWit layout; `id()` hashes exactly these bytes."""
        result = pack('<l', self.version)
        result += compact_size(len(self.vin))
        for i in self.vin:
            result += i.serialize()
        result += compact_size(len(self.vout))
        for o in self.vout:
            result += o.serialize()
        result += pack('<L', self.locktime)
        return result

    def has_witness(self) -> bool:
        """True when at least one input carries a non-empty stack."""
        return any(vin.witness for vin in self.vin)

    def serialize_wire(self) -> bytes:
        """The BIP-144 layout: marker/flag + witness stacks appear
        exactly when some input carries a witness stack; the output is
        byte-identical to `serialize_stripped` otherwise."""
        if not self.has_witness():
            return self.serialize_stripped()
        result = pack('<l', self.version)
        result += b'\x00\x01'  # marker || flag
        result += compact_size(len(self.vin))
        for i in self.vin:
            result += i.serialize()
        result += compact_size(len(self.vout))
        for o in self.vout:
            result += o.serialize()
        for i in self.vin:
            result += compact_size(len(i.witness))
            for item in i.witness:
                result += compact_size(len(item)) + item
        result += pack('<L', self.locktime)
        return result

    def id(self) -> bytes:
        """Txid in the display (reversed) byte order -- the same
        convention as `yubtc.transaction.CTransaction.id`; the Creator
        and Signer compare it against `PsbtTxIn.txhash` directly."""
        return dsha256(self.serialize_stripped())[::-1]


def _parse_tx(data: bytes, segwit_allowed: bool) -> PsbtTransaction:
    """Parse a transaction from `data`. When `segwit_allowed` the
    BIP-144 marker/flag layout is accepted (used for
    `NON_WITNESS_UTXO`, which may carry witness data); otherwise the
    stripped layout only (used for `UNSIGNED_TX`, which must never
    carry a witness). Counts and lengths use minimally-bounded
    CompactSize reads; any over-read or trailing bytes are
    `Truncated`."""
    r = _Reader(data)
    version = unpack('<l', r.read_array(4))[0]
    # BIP-144 detection: a stripped tx with >= 1 input cannot start its
    # vin count with 0x00, so `00 01` after the version is an
    # unambiguous marker/flag pair. (Same heuristic as Bitcoin Core.)
    segwit = (segwit_allowed and r.remaining() >= 2
              and r.peek(0) == 0x00 and r.peek(1) == 0x01)
    if segwit:
        r.take(2)
    n_vin = r.read_compact_size()
    # Each input occupies >= 41 bytes, so a count above the remaining
    # length is truncated data; this also bounds the loop below.
    if n_vin > r.remaining():
        raise Truncated()
    vin = []
    for _ in range(n_vin):
        txhash = r.read_array(32)
        n = unpack('<L', r.read_array(4))[0]
        script_len = r.read_compact_size()
        script = r.take(script_len)
        sequence = unpack('<L', r.read_array(4))[0]
        vin.append(PsbtTxIn(txhash=txhash, n=n, script=script,
                            sequence=sequence, witness=()))
    n_vout = r.read_compact_size()
    # Each output occupies >= 9 bytes -- same bound as the inputs.
    if n_vout > r.remaining():
        raise Truncated()
    vout = []
    for _ in range(n_vout):
        amount = unpack('<Q', r.read_array(8))[0]
        script_len = r.read_compact_size()
        vout.append(PsbtTxOut(amount=amount, script=r.take(script_len)))
    if segwit:
        vin = [vin_item._replace(witness=_parse_witness_section(r))
               for vin_item in vin]
    locktime = unpack('<L', r.read_array(4))[0]
    if not r.at_end():
        raise Truncated()
    return PsbtTransaction(version=version, vin=tuple(vin), vout=tuple(vout),
                           locktime=locktime)


def _parse_witness_section(r: _Reader) -> tuple:
    """One input's witness stack of the BIP-144 layout."""
    n_items = r.read_compact_size()
    if n_items > r.remaining():
        raise Truncated()
    stack = []
    for _ in range(n_items):
        item_len = r.read_compact_size()
        stack.append(r.take(item_len))
    return tuple(stack)


def _parse_witness_utxo(data: bytes) -> PsbtTxOut:
    """Parse a `WITNESS_UTXO` value: ``amount (u64 LE) ||
    compact_size || scriptPubKey``. Trailing bytes ->
    `InvalidFieldValue`."""
    r = _Reader(data)
    amount = unpack('<Q', r.read_array(8))[0]
    script_len = r.read_compact_size()
    script = r.take(script_len)
    if not r.at_end():
        raise InvalidFieldValue()
    return PsbtTxOut(amount=amount, script=script)


def _encode_witness_stack(items) -> bytes:
    """Serialize a witness stack (`FINAL_SCRIPTWITNESS` value): the
    ``compact_size`` element count followed by length-prefixed items."""
    out = bytearray()
    _write_compact_size(out, len(items))
    for item in items:
        _write_compact_size(out, len(item))
        out += item
    return bytes(out)


def _decode_witness_stack(data: bytes):
    """Decode a serialized witness stack. Raises `Truncated` on any
    malformed input (mapped by callers to `IncompleteInput`)."""
    r = _Reader(data)
    n_items = r.read_compact_size()
    if n_items > r.remaining():
        raise Truncated()
    stack = []
    for _ in range(n_items):
        item_len = r.read_compact_size()
        stack.append(r.take(item_len))
    if not r.at_end():
        raise Truncated()
    return stack


# --- Data types ---------------------------------------------------------


class UnknownKv(NamedTuple):
    """An opaque key/value pair preserved byte-for-byte through the
    whole pipeline. `key` includes the field-type prefix exactly as it
    appeared on the wire."""
    key: bytes
    value: bytes


class PsbtIn(object):
    """Per-input PSBT map (the in-scope typed fields + opaque
    passthrough; mirrors the Rust `PsbtInput`). Every field must be
    passed by name; ``None`` is the legitimate "field absent" value."""

    @require_kwargs_only
    def __init__(self, non_witness_utxo=None, witness_utxo=None,
                 partial_sigs=None, sighash_type=None, redeem_script=None,
                 witness_script=None, final_scriptsig=None,
                 final_scriptwitness=None, unknown=None):
        self.non_witness_utxo = non_witness_utxo
        self.witness_utxo = witness_utxo
        self.partial_sigs = partial_sigs
        self.sighash_type = sighash_type
        self.redeem_script = redeem_script
        self.witness_script = witness_script
        self.final_scriptsig = final_scriptsig
        self.final_scriptwitness = final_scriptwitness
        self.unknown = unknown

    def __eq__(self, other):
        return isinstance(other, PsbtIn) and self.__dict__ == other.__dict__


def _empty_input() -> PsbtIn:
    """The all-unset input map (mirrors `PsbtInput::default`)."""
    return PsbtIn(non_witness_utxo=None, witness_utxo=None,
                  partial_sigs=[], sighash_type=None, redeem_script=None,
                  witness_script=None, final_scriptsig=None,
                  final_scriptwitness=None, unknown=[])


class PsbtOut(object):
    """Per-output PSBT map. yubtc writes no defined BIP-174 output
    fields -- everything is preserved as opaque pairs."""

    @require_kwargs_only
    def __init__(self, unknown: list = None):
        self.unknown = unknown

    def __eq__(self, other):
        return isinstance(other, PsbtOut) and self.__dict__ == other.__dict__


class PsbtInputSummary(NamedTuple):
    """Human-readable per-input line of `PsbtSummary` (`psbt decode`)."""
    has_utxo: bool
    n_partial_sigs: int
    sighash_type: Optional[int]
    finalized: bool


class PsbtOutputSummary(NamedTuple):
    """Human-readable per-output line of `PsbtSummary`."""
    amount_sat: int
    script_pubkey_hex: str


class PsbtSummary(NamedTuple):
    """Human-readable PSBT digest (`psbt decode`; not a BIP-174 role)."""
    txid_hex: str
    version: int
    inputs: tuple
    outputs: tuple
    fee_sat: Optional[int]


class CreateInput(NamedTuple):
    """Creator input descriptor: the UTXO metadata of one `vin` entry
    (mirrors the Rust `CreateInput`).

    `prev_tx` is the full previous transaction -- **required** for
    legacy (P2PKH) inputs and for P2SH-multisig inputs (Phase 15:
    both are legacy spends, it becomes the `NON_WITNESS_UTXO`
    field). Ignored for witness-form inputs (the Creator writes
    exactly one UTXO field per form, per spec).

    `redeem_script` (Phase 15) is the canonical bare CHECKMULTISIG
    redeem script of a P2SH-multisig input: it is validated against
    the `scriptPubKey` commitment and written as `REDEEM_SCRIPT
    (0x04)` -- the field becomes W/R on that path (preserve-only for
    every other form).

    `witness_script` (v0.3) is the canonical bare CHECKMULTISIG
    witness script of a P2WSH-multisig input: validated against the
    SHA-256 `scriptPubKey` commitment and written as `WITNESS_SCRIPT
    (0x05)` (W/R on that path; preserve-only otherwise) -- no
    `NON_WITNESS_UTXO`, no prev-tx fetch (BIP-143 commits the
    amount)."""
    amount: int
    script_pubkey: bytes
    prev_tx: Optional[PsbtTransaction]
    redeem_script: Optional[bytes] = None
    witness_script: Optional[bytes] = None


class Psbt(NamedTuple):
    """A parsed PSBT: the unsigned transaction plus one map per input
    and per output and the opaque global leftovers (mirrors the Rust
    `PartiallySignedTransaction`). Construct via `parse_psbt`,
    `create_psbt` or `from_base64`."""
    version: int
    unsigned_tx: PsbtTransaction
    inputs: list
    outputs: list
    unknown_global: list


# --- Signing-form dispatch ----------------------------------------------


def _pinned_sighash(form: tuple) -> int:
    """The sighash pinned for the form (ОВ-8): `SIGHASH_ALL` for the
    ECDSA forms, `SIGHASH_DEFAULT` for the P2TR key-path."""
    kind = form[0]
    if kind == 'p2tr':
        return PSBT_SIGHASH_DEFAULT
    return PSBT_SIGHASH_ALL


def _form_of_script(script_pubkey: bytes):
    """Strict form classification by `scriptPubKey` shape: ``('legacy',
    <20B hash>)``, ``('p2wpkh', <20B hash>)`` or ``('p2tr', <32B
    output key>)``. P2SH, P2WSH and anything non-canonical -> ``None``
    (unsupported for finalizing/extracting; the Signer answers
    `UnsupportedInputScript` separately)."""
    from yubtc.transaction import script2pkh
    from yubtc.script import extract_p2tr_output_key, extract_p2wpkh_hash
    try:
        return ('legacy', script2pkh(script=script_pubkey))
    except ValueError:
        pass
    try:
        return ('p2wpkh', extract_p2wpkh_hash(script=script_pubkey))
    except ValueError:
        pass
    try:
        return ('p2tr', extract_p2tr_output_key(script=script_pubkey))
    except ValueError:
        pass
    return None


def _is_p2sh_script(script: bytes) -> bool:
    """True when the script is a canonical P2SH (``a9 14 <20> 87``)."""
    from yubtc.script import OP_EQUAL, OP_HASH160
    return (len(script) == 23 and script[0] == OP_HASH160
            and script[1] == 0x14 and script[22] == OP_EQUAL)


def _is_p2wsh_script(script: bytes) -> bool:
    """True when the script is a canonical P2WSH (``00 20 <32>``)."""
    return len(script) == 34 and script[0] == 0x00 and script[1] == 0x20


def _own_form(script_pubkey: bytes, pubkey: bytes):
    """The script form this key commits to, ``None`` for foreign keys:
    hash160 commitment for P2PKH/P2WPKH, BIP-86 TapTweak commitment for
    P2TR key-path."""
    from yubtc.crypto import taproot_output_key
    from yubtc.hash import hash160
    pubhash = hash160(pubkey)
    form = _form_of_script(script_pubkey)
    if form is None:
        return None
    kind, committed = form
    if kind == 'p2tr':
        # `pubkey` is the wallet's own compressed key (a valid curve
        # point), so the tweak below cannot fail for it.
        tweaked = taproot_output_key(internal_xonly=pubkey[1:33])
        if tweaked != committed:
            return None
        return form
    if committed != pubhash:
        return None
    return form


def _blanked_serialization(tx: PsbtTransaction, index: int,
                           script_pubkey: bytes) -> bytes:
    """Legacy sighash preimage helper: the blanked stripped serialization
    with the signed input's `scriptSig` set to the UTXO `scriptPubKey`
    (the `build_vin` convention), ready for the sighash-type suffix."""
    blanked = PsbtTransaction(
        version=tx.version,
        vin=tuple(vin._replace(script=b'', witness=()) for vin in tx.vin),
        vout=tx.vout, locktime=tx.locktime)
    signed = blanked.vin[index]._replace(script=script_pubkey)
    preimage = PsbtTransaction(
        version=blanked.version,
        vin=blanked.vin[:index] + (signed,) + blanked.vin[index + 1:],
        vout=blanked.vout, locktime=blanked.locktime)
    return preimage.serialize_stripped()


def _insert_partial_sig(input_: PsbtIn, pubkey: bytes, sig: bytes) -> None:
    """Insert a partial signature keeping `partial_sigs` sorted by
    pubkey (deterministic serialization and KAT reproducibility)."""
    pos = 0
    for existing_key, _ in input_.partial_sigs:
        if existing_key <= pubkey:
            pos += 1
        else:
            break
    input_.partial_sigs.insert(pos, (pubkey, sig))


def _partial_sig_by_hash(input_: PsbtIn, hash_: bytes):
    """The partial signature whose pubkey commits to `hash_` (P2PKH /
    P2WPKH finalization dispatch)."""
    from yubtc.hash import hash160
    for pubkey, sig in input_.partial_sigs:
        if len(pubkey) != 33:
            continue
        if hash160(pubkey) != hash_:
            continue
        return pubkey, sig
    return None


def _p2tr_sig_by_output_key(input_: PsbtIn, output_key: bytes):
    """The 64-byte key-path signature whose pubkey tweaks to
    `output_key` (P2TR finalization dispatch). Foreign garbage keys are
    skipped: a 33-byte PSBT key is not guaranteed to be a valid curve
    point, and the tweak reports that as `TapTweakError`."""
    from yubtc.crypto import TapTweakError, taproot_output_key
    for pubkey, sig in input_.partial_sigs:
        if len(sig) != 64 or len(pubkey) != 33:
            continue
        try:
            tweaked = taproot_output_key(internal_xonly=pubkey[1:33])
        except TapTweakError:
            continue
        if tweaked == output_key:
            return sig
    return None


# --- Psbt construction (parse / create) ---------------------------------


def _parse_input_map(pairs: list) -> PsbtIn:
    """Interpret one input map's entries into a `PsbtIn`."""
    input_ = _empty_input()
    for key, value in pairs:
        ty, keydata = _split_key(key)
        if ty > 0xff:
            input_.unknown.append(UnknownKv(key=key, value=value))
            continue
        if ty == T_UNSIGNED_TX:
            # `NON_WITNESS_UTXO`: full previous tx, wire format
            # (witness allowed); must consume the value exactly.
            if keydata:
                raise InvalidKeyLength(field_type=T_UNSIGNED_TX)
            try:
                tx = _parse_tx(value, segwit_allowed=True)
            except PsbtError:
                raise InvalidFieldValue()
            input_.non_witness_utxo = tx
        elif ty == T_IN_WITNESS_UTXO:
            if keydata:
                raise InvalidKeyLength(field_type=T_IN_WITNESS_UTXO)
            input_.witness_utxo = _parse_witness_utxo(value)
        elif ty == T_PARTIAL_SIG:
            if not _pubkey_keydata_len(keydata):
                raise InvalidKeyLength(field_type=T_PARTIAL_SIG)
            input_.partial_sigs.append((keydata, value))
        elif ty == T_SIGHASH_TYPE:
            if keydata:
                raise InvalidKeyLength(field_type=T_SIGHASH_TYPE)
            if len(value) != 4:
                raise InvalidFieldValue()
            input_.sighash_type = unpack('<L', value)[0]
        elif ty == T_REDEEM_SCRIPT:
            if keydata:
                raise InvalidKeyLength(field_type=T_REDEEM_SCRIPT)
            input_.redeem_script = value
        elif ty == T_WITNESS_SCRIPT:
            if keydata:
                raise InvalidKeyLength(field_type=T_WITNESS_SCRIPT)
            input_.witness_script = value
        elif ty == T_IN_BIP32_DERIVATION:
            # Preserve-only; the pubkey key shape is still validated
            # (official BIP-174 invalid vector: 32-byte "pubkey").
            if not _pubkey_keydata_len(keydata):
                raise InvalidKeyLength(field_type=T_IN_BIP32_DERIVATION)
            input_.unknown.append(UnknownKv(key=key, value=value))
        elif ty == T_FINAL_SCRIPTSIG:
            if keydata:
                raise InvalidKeyLength(field_type=T_FINAL_SCRIPTSIG)
            input_.final_scriptsig = value
        elif ty == T_FINAL_SCRIPTWITNESS:
            if keydata:
                raise InvalidKeyLength(field_type=T_FINAL_SCRIPTWITNESS)
            input_.final_scriptwitness = value
        else:
            input_.unknown.append(UnknownKv(key=key, value=value))
    return input_


def _parse_output_map(pairs: list) -> PsbtOut:
    """Interpret one output map's entries. yubtc writes no defined
    output fields, but the BIP-174 output key shapes are validated
    (`REDEEM_SCRIPT` 0x00 / `WITNESS_SCRIPT` 0x01 -- no keydata;
    `BIP32_DERIVATION` 0x02 -- pubkey keydata) before the pair is
    preserved."""
    output = PsbtOut(unknown=[])
    for key, value in pairs:
        ty, keydata = _split_key(key)
        if ty > 0xff:
            output.unknown.append(UnknownKv(key=key, value=value))
            continue
        if ty in (T_UNSIGNED_TX, T_IN_WITNESS_UTXO):
            # Per-output REDEEM_SCRIPT (0x00) / WITNESS_SCRIPT (0x01).
            if keydata:
                raise InvalidKeyLength(field_type=ty)
            output.unknown.append(UnknownKv(key=key, value=value))
        elif ty == T_PARTIAL_SIG:
            # Per-output BIP32_DERIVATION (0x02).
            if not _pubkey_keydata_len(keydata):
                raise InvalidKeyLength(field_type=T_PARTIAL_SIG)
            output.unknown.append(UnknownKv(key=key, value=value))
        else:
            output.unknown.append(UnknownKv(key=key, value=value))
    return output


@require_kwargs_only
def parse_psbt(data: bytes = NotNone) -> Psbt:
    """Parse a PSBT from its wire encoding.

    Applies the full validation ladder (spec.md «Валидация»): size
    cap, magic, map structure and terminators, key/value rules,
    duplicates, `UNSIGNED_TX` presence and semantics (parses as a
    stripped transaction, >= 1 output, no scriptSig data), version 0,
    and map counts matching the transaction."""
    data = bytes(data)
    if len(data) > PSBT_MAX_SIZE:
        raise TooLarge()
    if len(data) < len(MAGIC) or data[:len(MAGIC)] != MAGIC:
        raise InvalidMagic()
    r = _Reader(data[len(MAGIC):])

    global_pairs = _read_map(r)
    version = 0
    unsigned_tx = None
    unknown_global = []
    for key, value in global_pairs:
        ty, keydata = _split_key(key)
        if ty > 0xff:
            # Field types beyond the BIP-174 registry -- opaque.
            unknown_global.append(UnknownKv(key=key, value=value))
            continue
        if ty == T_UNSIGNED_TX:
            # `UNSIGNED_TX` -- "no key data" type.
            if keydata:
                raise InvalidKeyLength(field_type=T_UNSIGNED_TX)
            try:
                tx = _parse_tx(value, segwit_allowed=False)
            except PsbtError:
                raise InvalidUnsignedTx()
            if not tx.vout or any(vin.script for vin in tx.vin):
                raise InvalidUnsignedTx()
            unsigned_tx = tx
        elif ty == T_VERSION:
            if keydata:
                raise InvalidKeyLength(field_type=T_VERSION)
            if len(value) != 4:
                raise InvalidFieldValue()
            version = unpack('<L', value)[0]
            if version != 0:
                raise UnsupportedVersion(version=version)
        elif ty == T_GLOBAL_XPUB:
            # Preserve-only, but the BIP-defined key shape is still
            # validated: 78-byte serialized xpub. The value (master
            # fingerprint + derivation path) is carried opaque -- the
            # path is not interpreted.
            if len(keydata) != 78:
                raise InvalidKeyLength(field_type=T_GLOBAL_XPUB)
            unknown_global.append(UnknownKv(key=key, value=value))
        else:
            unknown_global.append(UnknownKv(key=key, value=value))
    if unsigned_tx is None:
        raise MissingUnsignedTx()

    inputs = []
    for _ in unsigned_tx.vin:
        if r.at_end():
            raise MapCountMismatch()
        inputs.append(_parse_input_map(_read_map(r)))
    outputs = []
    for _ in unsigned_tx.vout:
        if r.at_end():
            raise MapCountMismatch()
        outputs.append(_parse_output_map(_read_map(r)))
    if not r.at_end():
        # Leftover bytes: an all-zero tail is a stray second map
        # terminator (spec: «второй терминатор — Truncated»);
        # anything else is one map too many.
        if all(b == 0 for b in data[r.pos:]):
            raise Truncated()
        raise MapCountMismatch()
    return Psbt(version=version, unsigned_tx=unsigned_tx, inputs=inputs,
                outputs=outputs, unknown_global=unknown_global)


def _input_pairs(psbt: Psbt, input_: PsbtIn) -> list:
    """The typed + opaque pairs of one input map, pre-sorting."""
    pairs = []
    if input_.non_witness_utxo is not None:
        pairs.append((bytes([T_UNSIGNED_TX]),
                      input_.non_witness_utxo.serialize_wire()))
    if input_.witness_utxo is not None:
        value = bytearray()
        value += pack('<Q', input_.witness_utxo.amount)
        _write_compact_size(value, len(input_.witness_utxo.script))
        value += input_.witness_utxo.script
        pairs.append((bytes([T_IN_WITNESS_UTXO]), bytes(value)))
    for pubkey, sig in input_.partial_sigs:
        pairs.append((bytes([T_PARTIAL_SIG]) + pubkey, sig))
    if input_.sighash_type is not None:
        pairs.append((bytes([T_SIGHASH_TYPE]),
                      pack('<L', input_.sighash_type)))
    if input_.redeem_script is not None:
        pairs.append((bytes([T_REDEEM_SCRIPT]), input_.redeem_script))
    if input_.witness_script is not None:
        pairs.append((bytes([T_WITNESS_SCRIPT]), input_.witness_script))
    # BIP-174: an empty final scriptSig is serialized as "unset",
    # never as an empty value.
    if input_.final_scriptsig is not None and input_.final_scriptsig:
        pairs.append((bytes([T_FINAL_SCRIPTSIG]), input_.final_scriptsig))
    if (input_.final_scriptwitness is not None
            and input_.final_scriptwitness):
        pairs.append((bytes([T_FINAL_SCRIPTWITNESS]),
                      input_.final_scriptwitness))
    for kv in input_.unknown:
        pairs.append((kv.key, kv.value))
    return pairs


@require_kwargs_only
def serialize_psbt(psbt: Psbt = NotNone) -> bytes:
    """Serialize in canonical form: pairs of every map sorted by full
    key bytes (type, then keydata, lexicographic), maps in fixed order
    (global, inputs, outputs). ``serialize(parse(x)) == x`` holds for
    any canonically-ordered ``x``; one canonization pass is stable."""
    out = bytearray()
    out += MAGIC
    global_pairs = [(bytes([T_UNSIGNED_TX]),
                     psbt.unsigned_tx.serialize_stripped())]
    for kv in psbt.unknown_global:
        global_pairs.append((kv.key, kv.value))
    _write_map(out, global_pairs)
    for input_ in psbt.inputs:
        _write_map(out, _input_pairs(psbt, input_))
    for output in psbt.outputs:
        _write_map(out, [(kv.key, kv.value) for kv in output.unknown])
    return bytes(out)


@require_kwargs_only
def input_utxo_data(psbt: Psbt = NotNone, index: int = NotNone):
    """UTXO metadata of input `index`: ``(scriptPubKey, amount)`` taken
    from `WITNESS_UTXO` when present, else from the `vout` entry the
    input spends inside `NON_WITNESS_UTXO`. ``None`` when the input
    carries no usable UTXO data (the Signer silently skips such
    inputs -- BIP-174 MUST)."""
    if index >= len(psbt.inputs):
        return None
    input_ = psbt.inputs[index]
    if input_.witness_utxo is not None:
        return input_.witness_utxo.script, input_.witness_utxo.amount
    prev = input_.non_witness_utxo
    if prev is None:
        return None
    if index >= len(psbt.unsigned_tx.vin):
        return None
    n = psbt.unsigned_tx.vin[index].n
    if n >= len(prev.vout):
        return None
    out = prev.vout[n]
    return out.script, out.amount


def _spend_context(psbt: Psbt):
    """Per-input BIP-341 digest context: one `(amount, script_pubkey)`
    pair for every input of the transaction, from `input_utxo_data`.
    ``None`` when any input lacks UTXO data (a key-path P2TR digest
    commits to all inputs, so the input becomes unsignable rather than
    the whole signing pass failing)."""
    from yubtc.transaction import SpendInput
    inputs = []
    for i in range(len(psbt.unsigned_tx.vin)):
        data = input_utxo_data(psbt=psbt, index=i)
        if data is None:
            return None
        script_pubkey, amount = data
        inputs.append(SpendInput(amount=amount, script_pubkey=script_pubkey))
    return inputs


# --- Roles ---------------------------------------------------------------


@require_kwargs_only
def create_psbt(unsigned_tx: PsbtTransaction = NotNone,
                inputs: list = NotNone) -> Psbt:
    """Creator (+Updater, spec «Роли»): wrap an unsigned transaction
    and its UTXO metadata into a fresh PSBT.

    `unsigned_tx` must be truly unsigned -- empty `scriptSig` and
    empty witness stacks (the official BIP-174 vector with a filled
    scriptSig is exactly this refusal) -- with at least one output,
    and `inputs` must parallel `vin`. For every legacy (P2PKH) input
    and every P2SH-multisig input (Phase 15: `redeem_script` present,
    canonical, committed to by the `scriptPubKey`) a `prev_tx` whose
    txid matches the outpoint is required; witness-form inputs get a
    `WITNESS_UTXO` from ``(amount, script_pubkey)``. Known derivation
    data the wallet does not have (xpubs, BIP-32 paths) is
    deliberately not written (ОВ-9)."""
    if not unsigned_tx.vout:
        raise InvalidUnsignedTx()
    if len(unsigned_tx.vin) != len(inputs):
        raise MapCountMismatch()
    if any(vin.script or vin.witness for vin in unsigned_tx.vin):
        raise InvalidUnsignedTx()
    psbt_inputs = []
    for i, (vin, create) in enumerate(zip(unsigned_tx.vin, inputs)):
        from yubtc.hash import hash160
        from yubtc.script import extract_multisig_quorum
        form = _form_of_script(create.script_pubkey)
        if form is not None and form[0] == 'legacy':
            prev = create.prev_tx
            if prev is None:
                raise IncompleteInput(index=i)
            if prev.id() != vin.txhash:
                raise UtxoMismatch()
            psbt_inputs.append(PsbtIn(
                non_witness_utxo=prev, witness_utxo=None, partial_sigs=[],
                sighash_type=None, redeem_script=None, witness_script=None,
                final_scriptsig=None, final_scriptwitness=None, unknown=[]))
        elif (_is_p2sh_script(create.script_pubkey)
                and create.redeem_script is not None):
            # Phase 15 Creator branch (spec «PSBT: Creator, Signer и
            # Finalizer»): the input spends the P2SH of a known redeem
            # script -- an explicit-address multisig UTXO. The redeem
            # script must be canonical (R-MS-3) and hash to the
            # `scriptPubKey` commitment; the full prev tx is mandatory
            # (a P2SH input is legacy -- no witness discount, no
            # BIP-143 amount commitment).
            redeem = create.redeem_script
            try:
                extract_multisig_quorum(script=redeem)
            except ValueError:
                raise UnsupportedInputScript()
            committed = create.script_pubkey[2:22]
            if hash160(redeem) != committed:
                raise UtxoMismatch()
            prev = create.prev_tx
            if prev is None:
                raise IncompleteInput(index=i)
            if prev.id() != vin.txhash:
                raise UtxoMismatch()
            psbt_inputs.append(PsbtIn(
                non_witness_utxo=prev, witness_utxo=None,
                partial_sigs=[], sighash_type=None,
                redeem_script=redeem, witness_script=None,
                final_scriptsig=None, final_scriptwitness=None, unknown=[]))
        elif (_is_p2wsh_script(create.script_pubkey)
                and create.witness_script is not None):
            # v0.3 Creator branch (spec «P2WSH (v0.3)»): the input
            # spends the P2WSH of a known witness script -- the
            # witness form of the multisig quorum. The witness script
            # must be canonical (R-MS-3) and SHA-256-commit to the
            # `scriptPubKey` program; the UTXO rides as
            # `WITNESS_UTXO` (BIP-143 commits the amount -- no
            # `NON_WITNESS_UTXO`, no prev-tx fetch), and
            # `WITNESS_SCRIPT (0x05)` becomes W/R on this path.
            from yubtc.hash import sha256
            redeem = create.witness_script
            try:
                extract_multisig_quorum(script=redeem)
            except ValueError:
                raise UnsupportedInputScript()
            committed = create.script_pubkey[2:34]
            if sha256(redeem) != committed:
                raise UtxoMismatch()
            psbt_inputs.append(PsbtIn(
                non_witness_utxo=None,
                witness_utxo=PsbtTxOut(amount=create.amount,
                                       script=create.script_pubkey),
                partial_sigs=[], sighash_type=None, redeem_script=None,
                witness_script=redeem, final_scriptsig=None,
                final_scriptwitness=None, unknown=[]))
        else:
            psbt_inputs.append(PsbtIn(
                non_witness_utxo=None,
                witness_utxo=PsbtTxOut(amount=create.amount,
                                       script=create.script_pubkey),
                partial_sigs=[], sighash_type=None, redeem_script=None,
                witness_script=None, final_scriptsig=None,
                final_scriptwitness=None, unknown=[]))
    outputs = [PsbtOut(unknown=[]) for _ in unsigned_tx.vout]
    return Psbt(version=0, unsigned_tx=unsigned_tx, inputs=psbt_inputs,
                outputs=outputs, unknown_global=[])


@require_kwargs_only
def sign_psbt_input(psbt: Psbt = NotNone, index: int = NotNone,
                    privkey=NotNone) -> bool:
    """Signer, single input: add our `PARTIAL_SIG` to input `index` if
    `privkey` is the key of the UTXO backing it.

    Returns ``True`` when a signature was added (or was already
    present -- the operation is idempotent), ``False`` when the input
    cannot be signed with this key (no UTXO data, foreign script, or
    an incomplete BIP-341 digest context). Errors:
    `UnsupportedInputScript` for P2WSH-shaped UTXOs and for P2SH
    inputs whose `REDEEM_SCRIPT` is absent or not a canonical bare
    CHECKMULTISIG script (R-MS-3 -- yubtc does not sign or finalize
    such scripts; Phase 15), `UnsupportedSighashType` when the input
    pins a sighash other than the form's (ОВ-8 -- the wallet walk
    turns this into a silent skip), `UtxoMismatch` when a present
    `NON_WITNESS_UTXO` fails the txid check or a P2SH redeem script
    fails its `hash160` commitment (BIP-174 "Data Signers Check For").

    Digests reuse the Phase 13 machinery: legacy SIGHASH_ALL over the
    blanked serialization with the signed input's scriptCode -- the
    UTXO `scriptPubKey` for P2PKH (byte-identical to the
    `build_vin`-based signing) and the redeem script for
    P2SH-multisig (Phase 15; the same algorithm, parameterized
    scriptCode), BIP-143 for P2WPKH and BIP-341 key-path for P2TR
    (``aux_rand = 0x00 * 32``), so signatures match the direct path
    byte-for-byte (RFC6979 / BIP-340 determinism).

    P2SH-multisig identification is **membership, not script
    ownership** (R-MS-4): the P2SH `scriptPubKey` is never "ours" by
    shape, so the input is signed iff the key's compressed pubkey is
    one of the redeem script's N keys."""
    from yubtc.crypto import privkey2pubkey, sign_data
    data = input_utxo_data(psbt=psbt, index=index)
    if data is None:
        return False
    script_pubkey, amount = data
    if _is_p2wsh_script(script_pubkey):
        return _sign_psbt_input_p2wsh_multisig(psbt=psbt, index=index,
                                               privkey=privkey,
                                               amount=amount)
    if _is_p2sh_script(script_pubkey):
        return _sign_psbt_input_p2sh_multisig(psbt=psbt, index=index,
                                              privkey=privkey)
    pubkey = privkey2pubkey(privkey=privkey)
    form = _own_form(script_pubkey, pubkey)
    if form is None:
        return False
    pinned = _pinned_sighash(form)
    input_ = psbt.inputs[index]
    if input_.sighash_type is not None and input_.sighash_type != pinned:
        raise UnsupportedSighashType(sighash_type=input_.sighash_type)
    prev = input_.non_witness_utxo
    if prev is not None and prev.id() != psbt.unsigned_tx.vin[index].txhash:
        raise UtxoMismatch()
    if any(k == pubkey for k, _ in input_.partial_sigs):
        return True
    sighash_byte = pinned
    kind, committed = form
    if kind == 'legacy':
        preimage = (_blanked_serialization(psbt.unsigned_tx, index,
                                           script_pubkey)
                    + pack('<L', pinned))
        sig = sign_data(privkey=privkey, data=preimage) + bytes([sighash_byte])
    elif kind == 'p2wpkh':
        # The 26-byte BIP-143 scriptCode rebuilt from the witness
        # program: `0x19 0x76 0xa9 0x14 <20> 0x88 0xac`.
        script_code = p2wpkh_script_code(script_pubkey=script_pubkey)
        sighash = bip143_sighash(tx=psbt.unsigned_tx, input_index=index,
                                 script_code=script_code, amount=amount)
        from yubtc.crypto import sign_hash
        sig = sign_hash(privkey=privkey, datahash=sighash) \
            + bytes([sighash_byte])
    else:  # 'p2tr'
        spend = _spend_context(psbt)
        if spend is None:
            # BIP-341 commits to all inputs; without complete UTXO
            # data the digest is not computable -- skip.
            return False
        sighash = taproot_keypath_sighash(tx=psbt.unsigned_tx,
                                          input_index=index, spend=spend)
        sig = taproot_sign_sighash(privkey=privkey, sighash=sighash)
    _insert_partial_sig(input_, pubkey, sig)
    return True


def _sign_psbt_input_p2sh_multisig(psbt: Psbt, index: int, privkey) -> bool:
    """Signer, P2SH-multisig branch (Phase 15, spec «PSBT: Creator,
    Signer и Finalizer»): sign the legacy SIGHASH_ALL digest with
    `scriptCode = redeem` when the key's compressed pubkey is a member
    of the redeem script's quorum. See `sign_psbt_input` for the full
    contract; `index` must reference a canonical-P2SH input."""
    from yubtc.crypto import privkey2pubkey, sign_data
    from yubtc.hash import hash160
    from yubtc.script import InvalidMultisigRedeem, extract_multisig_quorum
    pubkey = privkey2pubkey(privkey=privkey)
    redeem = psbt.inputs[index].redeem_script
    if redeem is None:
        # P2SH without a redeem script: pre-Phase-15 refusal (yubtc
        # cannot know what the hash commits to).
        raise UnsupportedInputScript()
    # R-MS-3: only canonical bare CHECKMULTISIG redeem scripts are
    # signed; anything else (including duplicate keys) is refused.
    try:
        _, keys = extract_multisig_quorum(script=redeem)
    except InvalidMultisigRedeem:
        raise UnsupportedInputScript()
    # BIP-174 "Data Signers Check For": the redeem script must hash
    # to the commitment in the UTXO's P2SH scriptPubKey.
    script_pubkey = input_utxo_data(psbt=psbt, index=index)[0]
    if hash160(redeem) != script_pubkey[2:22]:
        raise UtxoMismatch()
    # Membership, not scriptPubKey shape (R-MS-4).
    if not any(k == pubkey for k in keys):
        return False
    input_ = psbt.inputs[index]
    # ОВ-8: the pinned sighash for the legacy ECDSA forms.
    if input_.sighash_type is not None \
            and input_.sighash_type != PSBT_SIGHASH_ALL:
        raise UnsupportedSighashType(sighash_type=input_.sighash_type)
    # BIP-174 "Data Signers Check For": the prev tx must hash to the
    # outpoint being spent.
    prev = input_.non_witness_utxo
    if prev is not None and prev.id() != psbt.unsigned_tx.vin[index].txhash:
        raise UtxoMismatch()
    # Idempotent: our signature is already in place.
    if any(k == pubkey for k, _ in input_.partial_sigs):
        return True
    # Legacy digest with scriptCode = redeem: the blanked
    # serialization restores the redeem script into the signed input's
    # `scriptSig` slot, then the SIGHASH_ALL suffix.
    preimage = (_blanked_serialization(psbt.unsigned_tx, index, redeem)
                + pack('<L', PSBT_SIGHASH_ALL))
    sig = sign_data(privkey=privkey, data=preimage) \
        + bytes([PSBT_SIGHASH_ALL])
    _insert_partial_sig(input_, pubkey, sig)
    return True


def _sign_psbt_input_p2wsh_multisig(psbt: Psbt, index: int, privkey,
                                    amount: int) -> bool:
    """Signer, P2WSH-multisig branch (v0.3, spec «P2WSH (v0.3)»): sign
    the BIP-143 SIGHASH_ALL digest with `scriptCode = redeem` when the
    key's compressed pubkey is a member of the witness script's
    quorum. See `sign_psbt_input` for the full contract; `index` must
    reference a canonical-P2WSH input and `amount` is the
    `WITNESS_UTXO` value the BIP-143 digest commits to."""
    from yubtc.crypto import privkey2pubkey, sign_hash
    from yubtc.hash import sha256
    from yubtc.script import (InvalidMultisigRedeem,
                              extract_multisig_quorum)
    pubkey = privkey2pubkey(privkey=privkey)
    redeem = psbt.inputs[index].witness_script
    if redeem is None:
        # P2WSH without a witness script: pre-v0.3 refusal (yubtc
        # cannot know what the SHA-256 commitment is).
        raise UnsupportedInputScript()
    # R-MS-3: only canonical bare CHECKMULTISIG witness scripts are
    # signed; anything else (including duplicate keys) is refused.
    try:
        _, keys = extract_multisig_quorum(script=redeem)
    except InvalidMultisigRedeem:
        raise UnsupportedInputScript()
    # BIP-174 "Data Signers Check For": the witness script must
    # SHA-256-commit to the program in the UTXO's P2WSH scriptPubKey.
    script_pubkey = input_utxo_data(psbt=psbt, index=index)[0]
    if sha256(redeem) != script_pubkey[2:34]:
        raise UtxoMismatch()
    # Membership, not scriptPubKey shape (R-MS-4).
    if not any(k == pubkey for k in keys):
        return False
    input_ = psbt.inputs[index]
    # ОВ-8: the pinned sighash for the BIP-143 ECDSA forms.
    if input_.sighash_type is not None \
            and input_.sighash_type != PSBT_SIGHASH_ALL:
        raise UnsupportedSighashType(sighash_type=input_.sighash_type)
    # BIP-174 "Data Signers Check For": a *present*
    # NON_WITNESS_UTXO must still hash to the outpoint being spent
    # (the field is optional for witness forms).
    prev = input_.non_witness_utxo
    if prev is not None and prev.id() != psbt.unsigned_tx.vin[index].txhash:
        raise UtxoMismatch()
    # Idempotent: our signature is already in place.
    if any(k == pubkey for k, _ in input_.partial_sigs):
        return True
    # BIP-143 digest with scriptCode = the serialized witness script
    # (`CompactSize(|redeem|) || redeem` -- the BIP-143 scriptCode
    # serialization, not an OP_PUSHDATA push), the amount committed
    # from the WITNESS_UTXO.
    script_code = compact_size(len(redeem)) + redeem
    sighash = bip143_sighash(tx=psbt.unsigned_tx, input_index=index,
                             script_code=script_code, amount=amount)
    sig = sign_hash(privkey=privkey, datahash=sighash) \
        + bytes([PSBT_SIGHASH_ALL])
    _insert_partial_sig(input_, pubkey, sig)
    return True


@require_kwargs_only
def combine_psbt(psbt: Psbt = NotNone, other: Psbt = NotNone) -> Psbt:
    """Combiner: merge `other` into a copy of `psbt`.

    PSBTs are identified by their global `UNSIGNED_TX` (byte
    equality) -- anything else is `ForeignTransaction`. Equal keys
    with equal values collapse to one pair; equal keys with different
    values are a deterministic `ConflictingField` refusal (spec
    decision -- no arbitrary pick); different keys of the same type
    are all kept. The merge is commutative for disjoint signers and
    idempotent."""
    if (psbt.unsigned_tx.serialize_stripped()
            != other.unsigned_tx.serialize_stripped()):
        raise ForeignTransaction()
    unknown_global = _merge_unknown(psbt.unknown_global,
                                    other.unknown_global)
    inputs = [_merge_input(a, b)
              for a, b in zip(psbt.inputs, other.inputs)]
    outputs = [PsbtOut(unknown=_merge_unknown(a.unknown, b.unknown))
               for a, b in zip(psbt.outputs, other.outputs)]
    return Psbt(version=psbt.version, unsigned_tx=psbt.unsigned_tx,
                inputs=inputs, outputs=outputs, unknown_global=unknown_global)


@require_kwargs_only
def finalize_psbt_input(psbt: Psbt = NotNone, index: int = NotNone) -> None:
    """Finalize a single input (spec «Finalizer»): when the input's
    form is complete, convert its `PARTIAL_SIG` into the final
    fields --

    - P2PKH: `FINAL_SCRIPTSIG` = ``push(sig || 0x01) || push(pubkey)``
      (the pushed on-chain layout, byte-identical to the direct-path
      `scriptSig` `CScript`);
    - P2WPKH: `FINAL_SCRIPTWITNESS` = ``[sig || 0x01, pubkey]``;
    - P2TR key-path: `FINAL_SCRIPTWITNESS` = ``[sig64]``.

    The finalizing signer is identified by key commitment: hash160
    match for P2PKH/P2WPKH, BIP-86 TapTweak match for P2TR. A
    signature whose sighash byte disagrees with the input's
    `SIGHASH_TYPE` (when present) or the form's pin blocks the input
    (BIP-174 MUST) -- reported as `IncompleteInput`. On success the
    intermediate fields (`PARTIAL_SIG`, `SIGHASH_TYPE`,
    `REDEEM/WITNESS_SCRIPT`) are removed; UTXO and unknown fields are
    preserved (BIP-174 mandate: the Extractor checks the final tx
    against the UTXOs).

    Phase 15 adds the P2SH-multisig path: a canonical-P2SH input with
    a `REDEEM_SCRIPT` is finalized when `hash160(redeem)` matches the
    `scriptPubKey` commitment and `PARTIAL_SIG` holds at least one
    valid-sighash signature for M of the script's N keys. The final
    `scriptSig` is assembled in *script* key order (R-MS-4), never in
    `PARTIAL_SIG` arrival order: `OP_0 ‖ push(sig ‖ 0x01)×M ‖
    push(redeem)` (R-MS-5). A non-canonical redeem script is
    `UnsupportedInputScript` (yubtc does not finalize foreign
    multisig forms)."""
    input_ = psbt.inputs[index] if index < len(psbt.inputs) else None
    if input_ is None:
        raise IncompleteInput(index=index)
    if (input_.final_scriptsig is not None
            or input_.final_scriptwitness is not None):
        return
    data = input_utxo_data(psbt=psbt, index=index)
    if data is None:
        raise IncompleteInput(index=index)
    script_pubkey = data[0]
    if _is_p2sh_script(script_pubkey):
        _finalize_psbt_input_p2sh_multisig(psbt=psbt, index=index,
                                           script_pubkey=script_pubkey)
        return
    if _is_p2wsh_script(script_pubkey):
        _finalize_psbt_input_p2wsh_multisig(psbt=psbt, index=index,
                                            script_pubkey=script_pubkey)
        return
    form = _form_of_script(script_pubkey)
    if form is None:
        raise IncompleteInput(index=index)
    pinned = _pinned_sighash(form)
    if input_.sighash_type is not None and input_.sighash_type != pinned:
        raise IncompleteInput(index=index)
    kind, committed = form
    if kind == 'legacy':
        from yubtc.script import CScript
        found = _partial_sig_by_hash(input_, committed)
        if found is None:
            raise IncompleteInput(index=index)
        pubkey, sig = found
        if not sig or sig[-1] != pinned:
            raise IncompleteInput(index=index)
        # The pushed on-chain layout (spec + the direct-path `CScript`):
        # `sig` already ends with the sighash byte, so
        # push(sig || 0x01) || push(pubkey) -- a raw concatenation
        # would be interpreted as opcodes and never validate.
        input_.final_scriptsig = bytes(CScript([sig, pubkey]))
    elif kind == 'p2wpkh':
        found = _partial_sig_by_hash(input_, committed)
        if found is None:
            raise IncompleteInput(index=index)
        pubkey, sig = found
        if not sig or sig[-1] != pinned:
            raise IncompleteInput(index=index)
        input_.final_scriptwitness = _encode_witness_stack([sig, pubkey])
    else:  # 'p2tr'
        sig = _p2tr_sig_by_output_key(input_, committed)
        if sig is None:
            raise IncompleteInput(index=index)
        input_.final_scriptwitness = _encode_witness_stack([sig])
    # Intermediates out, UTXOs and unknowns stay.
    input_.partial_sigs = []
    input_.sighash_type = None
    input_.redeem_script = None
    input_.witness_script = None


@require_kwargs_only
def _finalize_psbt_input_p2sh_multisig(psbt: Psbt, index: int,
                                       script_pubkey: bytes) -> None:
    """Finalizer, P2SH-multisig branch (Phase 15). See
    `finalize_psbt_input` for the full contract; `index` must
    reference a canonical-P2SH input."""
    from yubtc.hash import hash160
    from yubtc.script import (InvalidMultisigRedeem,
                              extract_multisig_quorum,
                              make_multisig_script_sig)
    input_ = psbt.inputs[index]
    # A P2SH input is finalizable only with a known redeem script.
    redeem = input_.redeem_script
    if redeem is None:
        raise IncompleteInput(index=index)
    # R-MS-3: foreign (non-canonical) redeem scripts are refused, not
    # merely left incomplete.
    try:
        m, keys = extract_multisig_quorum(script=redeem)
    except InvalidMultisigRedeem:
        raise UnsupportedInputScript()
    # The redeem script must hash to the scriptPubKey commitment.
    if hash160(redeem) != script_pubkey[2:22]:
        raise UtxoMismatch()
    # ОВ-8: SIGHASH_ALL is pinned; anything else blocks the input.
    if input_.sighash_type is not None \
            and input_.sighash_type != PSBT_SIGHASH_ALL:
        raise IncompleteInput(index=index)
    # One valid-sighash signature per participating script key.
    # CHECKMULTISIG matching is greedy, so *any* M distinct member
    # keys can carry the spend: collect the signatures that are
    # present, in script-key order, and require at least M of them
    # (R-MS-4 -- the layout below follows script order; extra members
    # beyond the threshold are deterministically dropped from the
    # tail).
    member_sigs = []
    for key in keys:
        sig = next((s for pk, s in input_.partial_sigs if pk == key),
                   None)
        if sig is not None:
            if not sig or sig[-1] != PSBT_SIGHASH_ALL:
                raise IncompleteInput(index=index)
            member_sigs.append(sig)
    if len(member_sigs) < m:
        raise IncompleteInput(index=index)
    input_.final_scriptsig = make_multisig_script_sig(
        redeem=redeem, sigs=member_sigs[:m])
    # Intermediates out, UTXOs and unknowns stay.
    input_.partial_sigs = []
    input_.sighash_type = None
    input_.redeem_script = None
    input_.witness_script = None


def _finalize_psbt_input_p2wsh_multisig(psbt: Psbt, index: int,
                                        script_pubkey: bytes) -> None:
    """Finalizer, P2WSH-multisig branch (v0.3, spec «P2WSH (v0.3)»).
    See `finalize_psbt_input` for the full contract; `index` must
    reference a canonical-P2WSH input. The final
    `FINAL_SCRIPTWITNESS` is the BIP-141 stack -- empty-string dummy,
    the M signatures in script-key order, the witness script -- never
    a `scriptSig`."""
    from yubtc.hash import sha256
    from yubtc.script import (InvalidMultisigRedeem,
                              extract_multisig_quorum,
                              make_multisig_witness)
    input_ = psbt.inputs[index]
    # A P2WSH input is finalizable only with a known witness script.
    redeem = input_.witness_script
    if redeem is None:
        raise IncompleteInput(index=index)
    # R-MS-3: foreign (non-canonical) witness scripts are refused,
    # not merely left incomplete.
    try:
        m, keys = extract_multisig_quorum(script=redeem)
    except InvalidMultisigRedeem:
        raise UnsupportedInputScript()
    # The witness script must commit to the scriptPubKey program.
    if sha256(redeem) != script_pubkey[2:34]:
        raise UtxoMismatch()
    # ОВ-8: SIGHASH_ALL is pinned; anything else blocks the input.
    if input_.sighash_type is not None \
            and input_.sighash_type != PSBT_SIGHASH_ALL:
        raise IncompleteInput(index=index)
    # One valid-sighash signature per participating script key
    # (greedy CHECKMULTISIG semantics -- any M distinct members can
    # carry the spend; collected in script-key order, extras
    # truncated from the tail -- the Phase 15 rule, carried over).
    member_sigs = []
    for key in keys:
        sig = next((s for pk, s in input_.partial_sigs if pk == key),
                   None)
        if sig is not None:
            if not sig or sig[-1] != PSBT_SIGHASH_ALL:
                raise IncompleteInput(index=index)
            member_sigs.append(sig)
    if len(member_sigs) < m:
        raise IncompleteInput(index=index)
    input_.final_scriptwitness = _encode_witness_stack(
        make_multisig_witness(redeem=redeem, sigs=member_sigs[:m]))
    # Intermediates out, UTXOs and unknowns stay.
    input_.partial_sigs = []
    input_.sighash_type = None
    input_.redeem_script = None
    input_.witness_script = None


def finalize_psbt(psbt: Psbt = NotNone) -> None:
    """Finalizer: finalize every input that is complete, leave the
    rest untouched (per-input operation; completeness of the whole
    transaction is the Extractor's rule). Already-finalized inputs are
    left as they are, so `finalize` is idempotent. Per-input errors
    (incomplete, unsupported/foreign multisig forms) are ignored --
    the Rust oracle's `let _ = self.finalize_input(i)`; the library
    primitive `finalize_psbt_input` reports them."""
    for i in range(len(psbt.inputs)):
        try:
            finalize_psbt_input(psbt=psbt, index=i)
        except PsbtError:
            pass


@require_kwargs_only
def extract_transaction(psbt: Psbt = NotNone) -> PsbtTransaction:
    """Extractor: require every input to be finalized, then build the
    wire-format transaction (`serialize_wire`; the marker/flag section
    appears exactly when some input carries a witness stack). The PSBT
    itself is not modified.

    Phase 15: a canonical-P2SH input (with a `REDEEM_SCRIPT`) is
    extracted via its `FINAL_SCRIPTSIG` -- like legacy -- and must not
    carry a witness stack (`IncompleteInput`). A P2SH input without a
    redeem script stays a foreign form yubtc cannot validate
    (`NotFinalized`)."""
    vin = []
    for i, input_ in enumerate(psbt.inputs):
        data = input_utxo_data(psbt=psbt, index=i)
        script_pubkey = None if data is None else data[0]
        form = None if data is None else _form_of_script(script_pubkey)
        if form is None:
            if data is not None and _is_p2sh_script(script_pubkey):
                # P2SH-multisig: legacy spend, no witness stack
                # (BIP-141 -- a witness would make it a nested SegWit
                # spend, explicitly rejected in Phase 13). Requires
                # FINAL_SCRIPTSIG, like legacy. (The Finalizer strips
                # the intermediate REDEEM_SCRIPT field, so
                # presence-based completeness is the check that
                # survives finalization.)
                if input_.final_scriptwitness is not None:
                    raise IncompleteInput(index=i)
                if input_.final_scriptsig is None:
                    raise NotFinalized()
                vin.append(psbt.unsigned_tx.vin[i]._replace(
                    script=input_.final_scriptsig))
                continue
            if data is not None and _is_p2wsh_script(script_pubkey):
                # P2WSH-multisig (v0.3): witness spend, no scriptSig
                # (a pushed scriptSig on a witness v0 output is not a
                # form yubtc builds -- the symmetrical refusal of the
                # P2SH arm's witness check). Requires
                # FINAL_SCRIPTWITNESS.
                if input_.final_scriptsig is not None:
                    raise IncompleteInput(index=i)
                if input_.final_scriptwitness is None:
                    raise NotFinalized()
                try:
                    stack = _decode_witness_stack(
                        input_.final_scriptwitness)
                except PsbtError:
                    raise IncompleteInput(index=i)
                vin.append(psbt.unsigned_tx.vin[i]._replace(
                    script=b'', witness=tuple(stack)))
                continue
            # Without a recognizable UTXO form the Extractor cannot
            # validate completeness -- refuse (BIP-174 Extractor MUST
            # check).
            raise NotFinalized()
        kind = form[0]
        if kind == 'legacy':
            script = input_.final_scriptsig
            if script is None:
                raise NotFinalized()
            vin.append(psbt.unsigned_tx.vin[i]._replace(script=script))
        else:
            stack_bytes = input_.final_scriptwitness
            if stack_bytes is None:
                raise NotFinalized()
            try:
                stack = _decode_witness_stack(stack_bytes)
            except PsbtError:
                raise IncompleteInput(index=i)
            vin.append(psbt.unsigned_tx.vin[i]._replace(
                script=b'', witness=tuple(stack)))
    return PsbtTransaction(version=psbt.unsigned_tx.version,
                           vin=tuple(vin), vout=psbt.unsigned_tx.vout,
                           locktime=psbt.unsigned_tx.locktime)


@require_kwargs_only
def psbt_summary(psbt: Psbt = NotNone) -> PsbtSummary:
    """Human-readable digest (`psbt decode`; a yubtc extension, not a
    BIP-174 role)."""
    credit_sat = 0
    all_inputs_known = True
    for i in range(len(psbt.inputs)):
        data = input_utxo_data(psbt=psbt, index=i)
        if data is None:
            all_inputs_known = False
        else:
            credit_sat += data[1]
    spend_sat = sum(out.amount for out in psbt.unsigned_tx.vout)
    fee_sat = None
    if all_inputs_known:
        fee = credit_sat - spend_sat
        if 0 <= fee <= 0xffffffffffffffff:
            fee_sat = fee
    return PsbtSummary(
        txid_hex=psbt.unsigned_tx.id().hex(),
        version=psbt.version,
        inputs=tuple(PsbtInputSummary(
            has_utxo=input_.witness_utxo is not None
            or input_.non_witness_utxo is not None,
            n_partial_sigs=len(input_.partial_sigs),
            sighash_type=input_.sighash_type,
            finalized=input_.final_scriptsig is not None
            or input_.final_scriptwitness is not None)
            for input_ in psbt.inputs),
        outputs=tuple(PsbtOutputSummary(
            amount_sat=out.amount,
            script_pubkey_hex=out.script.hex())
            for out in psbt.unsigned_tx.vout),
        fee_sat=fee_sat)


# --- merge helpers (combine) ---------------------------------------------


def _merge_unknown(a: list, b: list) -> list:
    """Merge opaque pair lists: identical keys must carry identical
    values (`ConflictingField` otherwise), new keys are appended."""
    out = list(a)
    for kv in b:
        existing = next((x for x in out if x.key == kv.key), None)
        if existing is not None:
            if existing.value != kv.value:
                raise ConflictingField()
        else:
            out.append(kv)
    return out


def _merge_field(a, b):
    """Merge one optional typed field: absent sides are filled from the
    other, both-present must be equal."""
    if a is None:
        return b
    if b is None:
        return a
    if a == b:
        return a
    raise ConflictingField()


def _merge_input(a: PsbtIn, b: PsbtIn) -> PsbtIn:
    """Merge two input maps (see `combine_psbt`)."""
    partial_sigs = list(a.partial_sigs)
    for pubkey, sig in b.partial_sigs:
        existing = next((x for x in partial_sigs if x[0] == pubkey), None)
        if existing is not None:
            if existing[1] != sig:
                raise ConflictingField()
        else:
            partial_sigs.append((pubkey, sig))
    partial_sigs.sort(key=lambda item: item[0])
    return PsbtIn(
        non_witness_utxo=_merge_field(a.non_witness_utxo,
                                      b.non_witness_utxo),
        witness_utxo=_merge_field(a.witness_utxo, b.witness_utxo),
        partial_sigs=partial_sigs,
        sighash_type=_merge_field(a.sighash_type, b.sighash_type),
        redeem_script=_merge_field(a.redeem_script, b.redeem_script),
        witness_script=_merge_field(a.witness_script, b.witness_script),
        final_scriptsig=_merge_field(a.final_scriptsig, b.final_scriptsig),
        final_scriptwitness=_merge_field(a.final_scriptwitness,
                                         b.final_scriptwitness),
        unknown=_merge_unknown(a.unknown, b.unknown))


# --- base64 transport (RFC 4648 §4, hand-rolled like the Rust oracle) ----

_B64_ALPHABET = (b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                 b'abcdefghijklmnopqrstuvwxyz0123456789+/')


@require_kwargs_only
def encode_base64(data: bytes = NotNone) -> str:
    """Base64-encode `data` with the standard alphabet and ``=``
    padding (BIP-174's transport encoding; no new dependencies, same
    policy as the hand-rolled bech32 codec of the Rust port)."""
    data = bytes(data)
    out = []
    for chunk in (data[i:i + 3] for i in range(0, len(data), 3)):
        b1 = chunk[1] if len(chunk) > 1 else 0
        b2 = chunk[2] if len(chunk) > 2 else 0
        n = (chunk[0] << 16) | (b1 << 8) | b2
        out.append(chr(_B64_ALPHABET[(n >> 18) & 63]))
        out.append(chr(_B64_ALPHABET[(n >> 12) & 63]))
        out.append(chr(_B64_ALPHABET[(n >> 6) & 63])
                   if len(chunk) > 1 else '=')
        out.append(chr(_B64_ALPHABET[n & 63]) if len(chunk) > 2 else '=')
    return ''.join(out)


def _b64_value_of(c: int) -> int:
    if 0x41 <= c <= 0x5a:  # 'A'..'Z'
        return c - 0x41
    if 0x61 <= c <= 0x7a:  # 'a'..'z'
        return c - 0x61 + 26
    if 0x30 <= c <= 0x39:  # '0'..'9'
        return c - 0x30 + 52
    if c == 0x2b:  # '+'
        return 62
    if c == 0x2f:  # '/'
        return 63
    raise InvalidFieldValue()


@require_kwargs_only
def decode_base64(s: str = NotNone) -> bytes:
    """Base64-decode `s` (standard alphabet, ``=`` padding). Leading
    and trailing ASCII whitespace is ignored; any other deviation --
    length not a multiple of 4, unknown characters, padding in the
    wrong place -- is `InvalidFieldValue` (the transport-level
    encoding error maps onto the shared "malformed value" variant)."""
    # Byte semantics mirror the Rust oracle: the (utf-8) bytes of the
    # whitespace-trimmed string are decoded; a non-ASCII byte fails in
    # `_b64_value_of` exactly as any other unknown character.
    trimmed = s.strip(' \t\n\r\f').encode('utf-8')
    if len(trimmed) % 4 != 0:
        raise InvalidFieldValue()
    out = bytearray()
    for quad in (trimmed[i:i + 4] for i in range(0, len(trimmed), 4)):
        vals = [0, 0, 0, 0]
        n_data = 4
        for i, c in enumerate(quad):
            if c == 0x3d:  # '='
                # Padding may only shorten the final group from the
                # third character on.
                n_data = min(n_data, i)
            else:
                if i >= n_data:
                    raise InvalidFieldValue()
                vals[i] = _b64_value_of(c)
        if n_data < 2:
            raise InvalidFieldValue()
        packed = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]
        out.append((packed >> 16) & 0xff)
        if n_data >= 3:
            out.append((packed >> 8) & 0xff)
        if n_data >= 4:
            out.append(packed & 0xff)
    return bytes(out)


@require_kwargs_only
def from_base64(s: str = NotNone) -> Psbt:
    """Parse from the base64 transport encoding (one line, BIP-174's
    `psbt` string). See `decode_base64` for the accepted grammar."""
    return parse_psbt(data=decode_base64(s=s))


@require_kwargs_only
def to_base64(psbt: Psbt = NotNone) -> str:
    """Render in canonical wire form and base64-encode -- the string
    form every role outputs."""
    return encode_base64(data=serialize_psbt(psbt=psbt))


# --- Signer walk (ОВ-9) ---------------------------------------------------


@require_kwargs_only
def sign_psbt(seed: str = NotNone, passphrase: str = NotNone,
              kdf: str = NotNone, psbt: Psbt = NotNone) -> list:
    """Signer role over the whole PSBT (spec «Роли», Signer + ОВ-9):
    a stateless wallet has no UTXO->key map, so "own" inputs are found
    by a bounded offline walk -- for every nonce
    ``0..PSBT_SIGN_MAX_NONCE`` and all three address forms, the derived
    `scriptPubKey` is matched against each input's UTXO field; a match
    signs (`sign_psbt_input`).

    Per BIP-174 the Signer only *adds* data and never has to sign
    everything: inputs without UTXO data, foreign inputs and inputs
    keyed beyond the nonce bound stay unsigned (their indices are
    returned so the caller can report them). A pinned-sighash mismatch
    (`UnsupportedSighashType`) also leaves the input unsigned (ОВ-8);
    every other error (`UtxoMismatch`, `UnsupportedInputScript`)
    aborts the walk. Everything not ours -- including unknown pairs --
    is carried through untouched. Mutates `psbt` in place."""
    from yubtc.crypto import seed2privkey
    from yubtc.fwd import ADDR_TYPES
    n_inputs = len(psbt.inputs)
    signed = [False] * n_inputs
    nonce = 0
    while nonce < PSBT_SIGN_MAX_NONCE:
        if all(signed):
            break
        for form in ADDR_TYPES:
            # The walk derives at construction-validated (seed,
            # passphrase, kdf) triples; KDF failure is impossible for
            # data that produced a wallet -- documented invariant.
            key = seed2privkey(seed=seed, nonce=nonce,
                               passphrase=passphrase, kdf=kdf,
                               addr_type=form)
            for i in range(n_inputs):
                if signed[i]:
                    continue
                try:
                    ok = sign_psbt_input(psbt=psbt, index=i, privkey=key)
                except UnsupportedSighashType:
                    # ОВ-8: an input that demands a different sighash
                    # is simply not signed.
                    continue
                if ok:
                    signed[i] = True
        nonce += 1
    return [i for i in range(n_inputs) if not signed[i]]
