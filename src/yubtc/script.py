"""Minimal Bitcoin script utilities for the yubtc wallet.

The opcode enumeration is kept intact (it's a stable public reference),
but the heavyweight machinery from python-bitcoinlib (CScriptOp encoders,
script builder, evaluator, sighash) has been removed because no live
code path touches it.

What the wallet actually uses:
- `CScript`: a bytes subclass that builds a script from an iterable of
  `CScriptOp` and short byte strings.
- `OP_DUP`, `OP_HASH160`, `OP_EQUALVERIFY`, `OP_CHECKSIG`, `OP_EQUAL`
  (the five opcodes that make up P2PKH and P2SH scripts).
- Phase 13: the native-SegWit witness lock scripts (`OP_0`/`OP_1`
  shapes) with their strict extractors -- see the bottom of this file.
- Phase 15 (multi-sig, mirrors the multisig half of
  `yubtc core/src/script.rs`): `push_data`/`push_data_len` (the
  scriptSig push encodings, escalating to OP_PUSHDATA1/2),
  `make_multisig_redeem_script` (canonical bare
  `OP_m ‖ (0x21 ‖ pubkey)×N ‖ OP_n ‖ OP_CHECKMULTISIG`, BIP-67
  sorted), `extract_multisig_quorum` (the strict shape-check
  counterpart), `make_multisig_script_sig` (the R-MS-5 finalize
  layout) and `redeem2p2sh_addr` (the quorum `3...` address).
- v0.3 (multi-sig P2WSH + P2TR script-path, mirrors the same
  `script.rs`): `make_p2wsh_lock_script`/`extract_p2wsh_program`,
  `make_multisig_witness` (BIP-141), `redeem2p2wsh_addr`; and the
  Tapscript half -- `make_multisig_tapscript` (the R-MS-7
  CHECKSIGADD idiom), `extract_multisig_tapscript` (strict
  shape-check), `tapscript_leaf_hash` (BIP-341 hashTapLeaf),
  `make_multisig_tapscript_witness` (R-MS-11 reverse slots) and
  `redeem2taproot_addr` (the quorum `bc1p...` address).
"""

from yubtc.util import NotNone, require_kwargs_only


class ScriptError(ValueError):
    """Typed script-shape failure (mirrors
    `yubtc core/src/script.rs::ScriptError`). The multisig surface
    raises `InvalidMultisigRedeem`; the Phase 13 extractors keep
    plain `ValueError` for continuity."""


class InvalidMultisigRedeem(ScriptError):
    """The script is not exactly the canonical bare CHECKMULTISIG
    redeem `OP_m ‖ (0x21 ‖ 33B compressed pubkey)×N ‖ OP_n ‖
    OP_CHECKMULTISIG` (R-MS-2/3 bounds, shapes, duplicates)."""

    default_message = 'invalid multisig redeem script'

    def __init__(self):
        super().__init__(self.default_message)


class InvalidMultisigTapscript(ScriptError):
    """A leaf script (or key set) did not pass the canonical
    tapscript CHECKSIGADD shape check (v0.3, R-MS-7; mirrors
    `script.rs::ScriptError::InvalidMultisigTapscript`): quorum
    bounds violated, non-x-only or duplicate key, a compressed-key
    push, an `OP_PUSHDATA` wrapper, a CHECKMULTISIG byte, or any byte
    layout other than `0x20‖pk_1 OP_CHECKSIG … 0x20‖pk_N
    OP_CHECKSIGADD OP_M ‖ terminator`."""

    default_message = 'invalid multisig tapscript'

    def __init__(self):
        super().__init__(self.default_message)


class CScriptOp(int):
    """A Bitcoin script opcode. Thin int subclass -- one byte on the wire."""
    __slots__ = ()


# push value
OP_0 = CScriptOp(0x00)
OP_FALSE = OP_0
OP_PUSHBYTES_20 = CScriptOp(0x14)
OP_PUSHBYTES_32 = CScriptOp(0x20)
OP_PUSHDATA1 = CScriptOp(0x4c)
OP_PUSHDATA2 = CScriptOp(0x4d)
OP_PUSHDATA4 = CScriptOp(0x4e)
OP_1NEGATE = CScriptOp(0x4f)
OP_RESERVED = CScriptOp(0x50)
OP_1 = CScriptOp(0x51)
OP_TRUE = OP_1
OP_2 = CScriptOp(0x52)
OP_3 = CScriptOp(0x53)
OP_4 = CScriptOp(0x54)
OP_5 = CScriptOp(0x55)
OP_6 = CScriptOp(0x56)
OP_7 = CScriptOp(0x57)
OP_8 = CScriptOp(0x58)
OP_9 = CScriptOp(0x59)
OP_10 = CScriptOp(0x5a)
OP_11 = CScriptOp(0x5b)
OP_12 = CScriptOp(0x5c)
OP_13 = CScriptOp(0x5d)
OP_14 = CScriptOp(0x5e)
OP_15 = CScriptOp(0x5f)
OP_16 = CScriptOp(0x60)

# control
OP_NOP = CScriptOp(0x61)
OP_VER = CScriptOp(0x62)
OP_IF = CScriptOp(0x63)
OP_NOTIF = CScriptOp(0x64)
OP_VERIF = CScriptOp(0x65)
OP_VERNOTIF = CScriptOp(0x66)
OP_ELSE = CScriptOp(0x67)
OP_ENDIF = CScriptOp(0x68)
OP_VERIFY = CScriptOp(0x69)
OP_RETURN = CScriptOp(0x6a)

# stack ops
OP_TOALTSTACK = CScriptOp(0x6b)
OP_FROMALTSTACK = CScriptOp(0x6c)
OP_2DROP = CScriptOp(0x6d)
OP_2DUP = CScriptOp(0x6e)
OP_3DUP = CScriptOp(0x6f)
OP_2OVER = CScriptOp(0x70)
OP_2ROT = CScriptOp(0x71)
OP_2SWAP = CScriptOp(0x72)
OP_IFDUP = CScriptOp(0x73)
OP_DEPTH = CScriptOp(0x74)
OP_DROP = CScriptOp(0x75)
OP_DUP = CScriptOp(0x76)
OP_NIP = CScriptOp(0x77)
OP_OVER = CScriptOp(0x78)
OP_PICK = CScriptOp(0x79)
OP_ROLL = CScriptOp(0x7a)
OP_ROT = CScriptOp(0x7b)
OP_SWAP = CScriptOp(0x7c)
OP_TUCK = CScriptOp(0x7d)

# splice ops
OP_CAT = CScriptOp(0x7e)
OP_SUBSTR = CScriptOp(0x7f)
OP_LEFT = CScriptOp(0x80)
OP_RIGHT = CScriptOp(0x81)
OP_SIZE = CScriptOp(0x82)

# bit logic
OP_INVERT = CScriptOp(0x83)
OP_AND = CScriptOp(0x84)
OP_OR = CScriptOp(0x85)
OP_XOR = CScriptOp(0x86)
OP_EQUAL = CScriptOp(0x87)
OP_EQUALVERIFY = CScriptOp(0x88)
OP_RESERVED1 = CScriptOp(0x89)
OP_RESERVED2 = CScriptOp(0x8a)

# numeric
OP_1ADD = CScriptOp(0x8b)
OP_1SUB = CScriptOp(0x8c)
OP_2MUL = CScriptOp(0x8d)
OP_2DIV = CScriptOp(0x8e)
OP_NEGATE = CScriptOp(0x8f)
OP_ABS = CScriptOp(0x90)
OP_NOT = CScriptOp(0x91)
OP_0NOTEQUAL = CScriptOp(0x92)

OP_ADD = CScriptOp(0x93)
OP_SUB = CScriptOp(0x94)
OP_MUL = CScriptOp(0x95)
OP_DIV = CScriptOp(0x96)
OP_MOD = CScriptOp(0x97)
OP_LSHIFT = CScriptOp(0x98)
OP_RSHIFT = CScriptOp(0x99)

OP_BOOLAND = CScriptOp(0x9a)
OP_BOOLOR = CScriptOp(0x9b)
OP_NUMEQUAL = CScriptOp(0x9c)
OP_NUMEQUALVERIFY = CScriptOp(0x9d)
OP_NUMNOTEQUAL = CScriptOp(0x9e)
OP_LESSTHAN = CScriptOp(0x9f)
OP_GREATERTHAN = CScriptOp(0xa0)
OP_LESSTHANOREQUAL = CScriptOp(0xa1)
OP_GREATERTHANOREQUAL = CScriptOp(0xa2)
OP_MIN = CScriptOp(0xa3)
OP_MAX = CScriptOp(0xa4)

OP_WITHIN = CScriptOp(0xa5)

# crypto
OP_RIPEMD160 = CScriptOp(0xa6)
OP_SHA1 = CScriptOp(0xa7)
OP_SHA256 = CScriptOp(0xa8)
OP_HASH160 = CScriptOp(0xa9)
OP_HASH256 = CScriptOp(0xaa)
OP_CODESEPARATOR = CScriptOp(0xab)
OP_CHECKSIG = CScriptOp(0xac)
OP_CHECKSIGVERIFY = CScriptOp(0xad)
OP_CHECKMULTISIG = CScriptOp(0xae)
OP_CHECKMULTISIGVERIFY = CScriptOp(0xaf)

# expansion
OP_NOP1 = CScriptOp(0xb0)
OP_NOP2 = CScriptOp(0xb1)
OP_CHECKLOCKTIMEVERIFY = OP_NOP2
OP_NOP3 = CScriptOp(0xb2)
OP_NOP4 = CScriptOp(0xb3)
OP_NOP5 = CScriptOp(0xb4)
OP_NOP6 = CScriptOp(0xb5)
OP_NOP7 = CScriptOp(0xb6)
OP_NOP8 = CScriptOp(0xb7)
OP_NOP9 = CScriptOp(0xb8)
OP_NOP10 = CScriptOp(0xb9)

# template matching params
OP_SMALLINTEGER = CScriptOp(0xfa)
OP_PUBKEYS = CScriptOp(0xfb)
OP_PUBKEYHASH = CScriptOp(0xfd)
OP_PUBKEY = CScriptOp(0xfe)

OP_INVALIDOPCODE = CScriptOp(0xff)


class CScript(bytes):
    """A serialized Bitcoin script.

    `bytes` subclass so it interoperates transparently with the byte fields
    on `CIn` and `COut`. Construction accepts either bytes directly or an
    iterable of `CScriptOp` and bytes (the latter as inline PUSHDATA).
    """
    def __new__(cls, value: object = None) -> 'CScript':
        if value is None:
            raise TypeError('value not set')
        if isinstance(value, (bytes, bytearray)):
            return super().__new__(cls, bytes(value))
        parts = []
        for item in value:
            if isinstance(item, CScriptOp):
                parts.append(bytes([item]))
            elif isinstance(item, (bytes, bytearray)):
                # Inline pushdata: 1-byte length prefix + N bytes. The
                # wallet only ever pushes 20-byte hashes here, so the
                # longer PUSHDATA1/2/4 encodings are not implemented.
                d = bytes(item)
                if len(d) >= 0x4c:
                    raise ValueError('pushdata too long for inline encoding')
                parts.append(bytes([len(d)]) + d)
            else:
                raise TypeError(f'cannot coerce {type(item).__name__} to CScript element')
        return super().__new__(cls, b''.join(parts))


# --- Witness lock scripts (Phase 13; mirrors core/src/script.rs) ------
#
# The wallet builds only the two canonical native-SegWit lock scripts
# and recognises them back with strict shape checks (no generic script
# decoder): `OP_0 OP_PUSHBYTES_20 <20B>` for P2WPKH (22 bytes) and
# `OP_1 OP_PUSHBYTES_32 <32B>` for P2TR (34 bytes).


@require_kwargs_only
def make_p2wpkh_lock_script(hash160: bytes = NotNone) -> CScript:
    """Build the canonical P2WPKH witness lock script for a 20-byte
    hash160 (native SegWit, witness version 0).

    Layout: `OP_0 OP_PUSHBYTES_20 <20 bytes>` -- exactly 22 bytes
    (`00 14 <hash>`). This is the `scriptPubKey` corresponding to a
    `bc1q...` address."""
    hash160 = bytes(hash160)
    if len(hash160) != 20:
        raise ValueError(f'hash160 must be 20 bytes, got {len(hash160)}')
    return CScript(bytes([OP_0, OP_PUSHBYTES_20]) + hash160)


@require_kwargs_only
def make_p2tr_lock_script(output_key: bytes = NotNone) -> CScript:
    """Build the canonical P2TR witness lock script for a 32-byte
    x-only output key (witness version 1, BIP-341/Taproot).

    Layout: `OP_1 OP_PUSHBYTES_32 <32 bytes>` -- exactly 34 bytes
    (`51 20 <key>`). This is the `scriptPubKey` corresponding to a
    `bc1p...` address."""
    output_key = bytes(output_key)
    if len(output_key) != 32:
        raise ValueError(f'output key must be 32 bytes, got {len(output_key)}')
    return CScript(bytes([OP_1, OP_PUSHBYTES_32]) + output_key)


@require_kwargs_only
def extract_p2wpkh_hash(script: bytes = NotNone) -> bytes:
    """Extract the 20-byte hash160 from a canonical P2WPKH witness
    script.

    Strict shape check (like `transaction.script2pkh`, not a general
    script decoder): the script must be exactly `00 14 <20 bytes>` --
    22 bytes. Anything else is rejected with `ValueError('invalid
    script: expected P2WPKH layout, got N bytes')`."""
    script = bytes(script)
    if (len(script) != 22
            or script[0] != OP_0
            or script[1] != OP_PUSHBYTES_20):
        raise ValueError(f'invalid script: expected P2WPKH layout, got {len(script)} bytes')
    return script[2:]


@require_kwargs_only
def extract_p2tr_output_key(script: bytes = NotNone) -> bytes:
    """Extract the 32-byte x-only output key from a canonical P2TR
    witness script.

    Strict shape check: the script must be exactly `51 20 <32 bytes>`
    -- 34 bytes. Anything else is rejected with `ValueError('invalid
    script: expected P2TR layout, got N bytes')`."""
    script = bytes(script)
    if (len(script) != 34
            or script[0] != OP_1
            or script[1] != OP_PUSHBYTES_32):
        raise ValueError(f'invalid script: expected P2TR layout, got {len(script)} bytes')
    return script[2:]


@require_kwargs_only
def make_p2wsh_lock_script(sha256: bytes = NotNone) -> CScript:
    """Build the canonical P2WSH witness lock script for a 32-byte
    SHA-256 commitment (native SegWit, witness version 0; v0.3,
    mirrors `script.rs::make_p2wsh_lock_script`).

    Layout: `OP_0 OP_PUSHBYTES_32 <32 bytes>` -- exactly 34 bytes
    (`00 20 <hash>`). This is the `scriptPubKey` of a `bc1q...` v0
    address carrying a 32-byte program; for the v0.3 multisig surface
    the commitment is `SHA256(redeem)` of the quorum's canonical
    redeem script."""
    sha256 = bytes(sha256)
    if len(sha256) != 32:
        raise ValueError(f'sha256 must be 32 bytes, got {len(sha256)}')
    return CScript(bytes([OP_0, OP_PUSHBYTES_32]) + sha256)


@require_kwargs_only
def extract_p2wsh_program(script: bytes = NotNone) -> bytes:
    """Extract the 32-byte SHA-256 commitment from a canonical P2WSH
    witness script.

    Strict shape check: the script must be exactly `00 20 <32 bytes>`
    -- 34 bytes. Anything else (other lengths, other witness versions,
    the 34-byte P2TR script `51 20 <32>`) is rejected with
    `ValueError('invalid script: expected P2WSH layout, got N
    bytes')`."""
    script = bytes(script)
    if (len(script) != 34
            or script[0] != OP_0
            or script[1] != OP_PUSHBYTES_32):
        raise ValueError(f'invalid script: expected P2WSH layout, got {len(script)} bytes')
    return script[2:]


# --- Multi-sig (Phase 15, P2SH; mirrors core/src/script.rs) ------------


@require_kwargs_only
def make_p2sh_lock_script(hash160: bytes = NotNone) -> CScript:
    """Build the canonical P2SH lock script for a 20-byte hash160.

    Layout: `OP_HASH160 <0x14> <20 bytes> OP_EQUAL` -- exactly 23
    bytes (`a9 14 <hash> 87`). This is the `scriptPubKey` behind a
    `3...` address; for the multisig wallet the hash is
    `hash160(redeem_script)`."""
    hash160 = bytes(hash160)
    if len(hash160) != 20:
        raise ValueError(f'hash160 must be 20 bytes, got {len(hash160)}')
    return CScript(bytes([OP_HASH160, 0x14]) + hash160 + bytes([OP_EQUAL]))


@require_kwargs_only
def push_data(data: bytes = NotNone) -> bytes:
    """Single-item data push: a length prefix followed by the item.

    Items up to `0x4b` bytes use the one-opcode form
    (`OP_PUSHBYTES_N`); 76-255 bytes escalate to `OP_PUSHDATA1` with
    an explicit one-byte length; 256-65535 bytes escalate to
    `OP_PUSHDATA2` with a little-endian two-byte length. The wallet's
    largest item is a 15-key redeem script (34·15 + 4 = 514 bytes), so
    `OP_PUSHDATA2` is the deepest encoding it ever needs. Longer
    items would need the 5/9-byte `OP_PUSHDATA4` encoding -- dead
    surface, rejected with `ValueError` instead of a silently
    malformed script."""
    data = bytes(data)
    if len(data) > 0xffff:
        raise ValueError(
            'item too long for a single/OP_PUSHDATA1/OP_PUSHDATA2 '
            'push: {} bytes'.format(len(data)))
    if len(data) <= 0x4b:
        return bytes([len(data)]) + data
    if len(data) <= 0xff:
        return bytes([OP_PUSHDATA1, len(data)]) + data
    return bytes([OP_PUSHDATA2]) + len(data).to_bytes(2, 'little') + data


@require_kwargs_only
def push_data_len(length: int = NotNone) -> int:
    """The on-wire length of `push_data` for an item of `length` bytes:
    1 for the single-opcode form, 2 for `OP_PUSHDATA1`, 3 for
    `OP_PUSHDATA2` (the spec's `pushlen(|redeem|)` in the multisig
    scriptSig size model)."""
    if length <= 0x4b:
        return 1
    if length <= 0xff:
        return 2
    return 3


def _op_n(n: int) -> int:
    """`OP_N` for N in `1..=16`: `0x50 + N` (single-byte `OP_1`...
    `OP_16` small-integer opcodes)."""
    return 0x50 + n


def _is_canonical_compressed_pubkey(key: bytes) -> bool:
    """The canonical compressed-pubkey shape accepted in a multisig
    redeem script: SEC prefix `02` (even Y) or `03` (odd Y)."""
    return key[0] == 0x02 or key[0] == 0x03


@require_kwargs_only
def make_multisig_redeem_script(m: int = NotNone,
                                keys: list = NotNone) -> bytes:
    """Build the canonical bare M-of-N CHECKMULTISIG redeem script
    (spec.md «Правила» R-MS-2/3/4).

    Layout: `OP_m ‖ (0x21 ‖ <33-byte compressed pubkey>)×N ‖ OP_n ‖
    OP_CHECKMULTISIG` -- nothing else is ever built or accepted.

    Validation:
    - **R-MS-2 (quorum bounds)**: `1 ≤ m ≤ len(keys) ≤ 15`
      (`yubtc.fwd.MS_MAX_PUBKEYS` -- above it the redeem script no
      longer fits the 520-byte MAX_SCRIPT_ELEMENT_SIZE consensus
      limit on a single push, so such a P2SH output is fundamentally
      unspendable);
    - **R-MS-3 (duplicates)**: two equal keys make the quorum
      degenerate (one key would have to supply two signatures) and
      are rejected.

    Every key must be exactly 33 bytes -- the runtime equivalent of
    the Rust oracle's `[[u8; 33]]` parameter type (the SEC 02/03
    prefix stays the extractor's check, as there).

    **R-MS-4 (BIP-67)**: the keys are sorted lexicographically by
    their 33 compressed bytes before assembly, so the same key *set*
    always yields the same redeem script -- and therefore the same
    P2SH address -- regardless of argument order. Signers place
    signatures by the *script's* key order
    (`extract_multisig_quorum` returns it), not by argument order.

    Every violation raises `InvalidMultisigRedeem` (the wallet maps
    bounds/duplicates onto the typed `MsError` variants at its own
    boundary)."""
    from yubtc.fwd import MS_MAX_PUBKEYS
    keys = [bytes(k) for k in keys]
    n = len(keys)
    if n == 0 or m == 0 or m > n or n > MS_MAX_PUBKEYS:
        raise InvalidMultisigRedeem()
    if any(len(k) != 33 for k in keys):
        raise InvalidMultisigRedeem()
    sorted_keys = sorted(keys)
    for first, second in zip(sorted_keys, sorted_keys[1:]):
        if first == second:
            raise InvalidMultisigRedeem()
    out = bytearray()
    out.append(_op_n(m))
    for key in sorted_keys:
        out.append(0x21)
        out += key
    out.append(_op_n(n))
    out.append(OP_CHECKMULTISIG)
    return bytes(out)


@require_kwargs_only
def extract_multisig_quorum(script: bytes = NotNone) -> tuple:
    """Extract the quorum `(m, keys)` from a canonical bare
    CHECKMULTISIG redeem script -- keys in **script order** (the order
    signatures must take in the final `scriptSig`, R-MS-4).

    Strict shape check, symmetric with `transaction.script2pkh` -- not
    a general script decoder: the script must be exactly
    `OP_m ‖ (0x21 ‖ 33-byte compressed pubkey)×N ‖ OP_n ‖
    OP_CHECKMULTISIG` with `1 ≤ m ≤ n ≤ 15`, no `OP_PUSHDATA`
    wrappers, no trailing bytes, and no duplicate keys (R-MS-3 --
    yubtc does not sign or finalize such scripts). Anything else
    raises `InvalidMultisigRedeem`."""
    from yubtc.fwd import MS_MAX_PUBKEYS
    script = bytes(script)
    # OP_m + one key push + OP_n + OP_CHECKMULTISIG is the minimum.
    if len(script) < 3 + 34:
        raise InvalidMultisigRedeem()
    m_op = script[0]
    n_op = script[len(script) - 2]
    if script[len(script) - 1] != OP_CHECKMULTISIG:
        raise InvalidMultisigRedeem()
    # Small-integer opcodes only, with the R-MS-2 bound (OP_16 would
    # be a 548-byte script -- unspendable).
    op_bound = 0x50 + MS_MAX_PUBKEYS
    if not (0x51 <= m_op <= op_bound) or not (0x51 <= n_op <= op_bound):
        raise InvalidMultisigRedeem()
    m = m_op - 0x50
    n = n_op - 0x50
    if m > n:
        raise InvalidMultisigRedeem()
    # The middle must be exactly N single-opcode 33-byte pushes.
    if len(script) - 3 != n * 34:
        raise InvalidMultisigRedeem()
    keys = []
    for i in range(n):
        start = 1 + i * 34
        if script[start] != 0x21:
            raise InvalidMultisigRedeem()
        key = script[start + 1:start + 34]
        if not _is_canonical_compressed_pubkey(key):
            raise InvalidMultisigRedeem()
        keys.append(key)
    # R-MS-3: duplicates make the quorum degenerate -- rejected.
    if len(set(keys)) != len(keys):
        raise InvalidMultisigRedeem()
    return m, keys


@require_kwargs_only
def make_multisig_script_sig(redeem: bytes = NotNone,
                             sigs: list = NotNone) -> bytes:
    """Assemble the finalized P2SH-multisig `scriptSig`
    (R-MS-4/R-MS-5):

    ```
    OP_0 ‖ push(sig_i ‖ 0x01)×M (in redeem-script key order) ‖ push(redeem)
    ```

    The leading `OP_0` is the empty-push dummy compensating the
    off-by-one stack error of `OP_CHECKMULTISIG` (R-MS-5 -- BIP-147
    NULLDUMMY makes a non-empty dummy consensus-invalid). `sigs` must
    already be ordered by the redeem script's key order -- the
    Finalizer derives that order from `extract_multisig_quorum`,
    never from `PARTIAL_SIG` arrival order -- and each element must
    be the complete `DER ‖ sighash` signature. The redeem script is
    pushed with `push_data` (its length can escalate to
    `OP_PUSHDATA1/2`)."""
    out = bytearray()
    out.append(OP_0)
    for sig in sigs:
        out += push_data(data=sig)
    out += push_data(data=redeem)
    return bytes(out)


@require_kwargs_only
def redeem2p2sh_addr(redeem: bytes = NotNone) -> str:
    """Redeem script -> mainnet P2SH address (`3...`, base58check with
    version `0x05`).

    The hash is `hash160(redeem)` -- the same commitment
    `make_p2sh_lock_script` embeds in the lock script, so an output
    paid to the returned address is spendable exactly by revealing
    and satisfying `redeem` (Phase 15: the multisig quorum address,
    ОВ-13 -- fixed by the `(N, M, keys)` tuple, no scan/gap walk)."""
    from yubtc.base58check import base58CheckEncode
    from yubtc.crypto import PREFIX_P2SH
    from yubtc.hash import hash160
    return base58CheckEncode(
        bytes([PREFIX_P2SH]) + hash160(bytes(redeem))).decode('ascii')


@require_kwargs_only
def make_multisig_witness(redeem: bytes = NotNone,
                          sigs: list = NotNone) -> list:
    """Assemble the finalized **P2WSH**-multisig witness stack (v0.3,
    spec.md «P2WSH (v0.3)», BIP-141; mirrors
    `script.rs::make_multisig_witness`):

        [<empty string> (CHECKMULTISIG dummy),
         push(sig_i || 0x01) x M (in redeem-script key order),
         <redeem>]

    `M + 2` items, signatures in the redeem script's key order. Unlike
    the P2SH `scriptSig` (`make_multisig_script_sig`) there is **no**
    separate `OP_0` byte: the BIP-141 dummy is a witness item of
    length zero, which serializes as a bare CompactSize `0x00` and
    *is* the empty push compensating the `OP_CHECKMULTISIG` off-by-one
    stack error (R-MS-5 semantics; BIP-147 NULLDUMMY satisfied -- the
    dummy is empty). The redeem script rides as the last witness
    item, never pushed through a `scriptSig`.

    `sigs` must already be ordered by the redeem script's key order
    and each element must be the complete `DER || sighash` signature.
    Returns the stack as a list of `bytes` items."""
    redeem = bytes(redeem)
    out = [b'']
    for sig in sigs:
        out.append(bytes(sig))
    out.append(redeem)
    return out


@require_kwargs_only
def redeem2p2wsh_addr(redeem: bytes = NotNone) -> str:
    """Redeem script -> mainnet P2WSH address (`bc1q...`, bech32
    witness version 0 with a 32-byte program; v0.3, mirrors
    `address.rs::redeem_to_p2wsh_address`).

    The commitment is `SHA256(redeem)` -- the same 32-byte value
    `make_p2wsh_lock_script` embeds in the witness lock script, so an
    output paid to the returned address is spendable exactly by
    revealing and satisfying `redeem` in the witness stack (the
    P2WSH counterpart of `redeem2p2sh_addr`: same redeem script,
    witness form -- ОВ-13 applies unchanged)."""
    from yubtc.bech32 import BECH32, bytes_to_5bit, encode
    from yubtc.crypto import HRP_MAINNET
    from yubtc.hash import sha256
    data = bytes([0]) + bytes_to_5bit(data=sha256(bytes(redeem)))
    return encode(hrp=HRP_MAINNET, encoding=BECH32, data=data)


# --- Multi-sig, P2TR script path (v0.3; mirrors core/src/script.rs) ----
#
# The Tapscript half of the quorum surface: the same M-of-N rule as the
# CHECKMULTISIG forms, executed by BIP-342 consensus through the
# CHECKSIGADD idiom (`OP_CHECKMULTISIG` is a disabled opcode under
# tapscript, so no mixed form exists). The canonical leaf is built and
# recognized in exactly one shape (R-MS-7); the finalized witness
# stacks the signature slots in reverse key order (R-MS-11) and there
# is no dummy element (no off-by-one to compensate -- R-MS-5 does not
# apply).

# `OP_CHECKSIGADD` (0xba, BIP-342). Pops a signature and a pubkey,
# verifies against the script-path sighash and adds the boolean result
# (1/0) to the numeric accumulator below -- the CHECKMULTISIG
# replacement of the tapscript idiom (R-MS-7).
OP_CHECKSIGADD = CScriptOp(0xba)

# The tapscript idiom's terminal opcode byte (v0.3, R-MS-7). Mirrors
# the Rust oracle's `script.rs::OP_NUMEQUAL` constant -- byte `0x9d`,
# pinned by both the spec text (`OP_NUMEQUAL (0x9d)`) and the oracle
# code (asserted in `script.rs` tests), so the mirror keeps it for
# bit-for-bit parity of every script, leaf hash, address and signature
# derived downstream. (Naming note: Bitcoin's consensus opcode table
# calls `0x9d` OP_NUMEQUALVERIFY and `0x9c` OP_NUMEQUAL; the
# accept/reject behaviour of the idiom is identical either way --
# success iff the counter equals M -- so the oracle's byte is mirrored
# as-is.)
TAPSCRIPT_NUMEQUAL = CScriptOp(0x9d)

# Leaf version byte of the canonical Tapscript quorum leaf (BIP-342):
# 0xc0 = leaf version 192, the only defined tapscript version. Enters
# the leaf hash (`0xc0 ‖ compact_size ‖ script`) and the control
# block's first byte (`c[0] = 0xc0 | parity(y(Q))`).
TAPSCRIPT_LEAF_VERSION = 0xc0


@require_kwargs_only
def make_multisig_tapscript(m: int = NotNone, keys: list = NotNone) -> bytes:
    """Build the canonical M-of-N tapscript leaf (v0.3, spec.md R-MS-7
    -- the BIP-342 «Alternatives to CHECKMULTISIG» idiom, Miniscript
    `multi_a`; mirrors `script.rs::make_multisig_tapscript`):

    ```
    0x20‖pk_1 OP_CHECKSIG 0x20‖pk_2 OP_CHECKSIGADD … 0x20‖pk_N
    OP_CHECKSIGADD OP_M ‖ terminator
    ```

    Every key push is exactly `0x20 ‖ <32 x-only bytes>` (33 bytes --
    BIP-340/342 keys are x-only in tapscript pushes); the first key's
    `OP_CHECKSIG (0xac)` result initializes the accumulator, keys
    `2..N` use `OP_CHECKSIGADD (0xba)`, and the final `OP_M (0x50+M)`
    compares the accumulated counter with the threshold (R-MS-7).
    Total size `34N + 2` -- 512 bytes at the maximal quorum (15 keys),
    inside the 520-byte MAX_SCRIPT_ELEMENT_SIZE limit the leaf
    element is subject to as an initial-stack item (R-MS-9: N = 16
    would produce 546 bytes -- consensus-invalid, refused here).

    Validation and determinism mirror `make_multisig_redeem_script`:
    `1 ≤ m ≤ n ≤ yubtc.fwd.MS_MAX_PUBKEYS`
    (`InvalidMultisigTapscript` otherwise), no duplicate keys, and
    **R-MS-4/R-MS-10 sorting**: the keys are sorted lexicographically
    by their 32 x-only bytes (sorting the compressed encodings would
    give a different order -- the same key set must always yield the
    same script and therefore the same address). Every key must be
    exactly 32 bytes -- the runtime equivalent of the Rust oracle's
    `[[u8; 32]]` parameter type."""
    from yubtc.fwd import MS_MAX_PUBKEYS
    keys = [bytes(k) for k in keys]
    n = len(keys)
    if n == 0 or m == 0 or m > n or n > MS_MAX_PUBKEYS:
        raise InvalidMultisigTapscript()
    if any(len(k) != 32 for k in keys):
        raise InvalidMultisigTapscript()
    sorted_keys = sorted(keys)
    if any(a == b for a, b in zip(sorted_keys, sorted_keys[1:])):
        raise InvalidMultisigTapscript()
    out = bytearray()
    for i, key in enumerate(sorted_keys):
        out.append(0x20)
        out += key
        out.append(OP_CHECKSIG if i == 0 else OP_CHECKSIGADD)
    out.append(_op_n(m))
    out.append(TAPSCRIPT_NUMEQUAL)
    return bytes(out)


@require_kwargs_only
def extract_multisig_tapscript(script: bytes = NotNone) -> tuple:
    """Extract the quorum `(m, keys)` from a canonical tapscript leaf
    -- keys in **script order** (the order the witness slots of the
    final spend follow, R-MS-11; mirrors
    `script.rs::extract_multisig_tapscript`).

    Strict shape check, symmetric with `extract_multisig_quorum` --
    not a general script decoder: the script must be exactly the
    R-MS-7 idiom with `1 ≤ m ≤ n ≤ yubtc.fwd.MS_MAX_PUBKEYS`,
    single-opcode `0x20` pushes only (no `OP_PUSHDATA` wrappers, no
    33-byte compressed keys), `OP_CHECKSIG` after the first key and
    `OP_CHECKSIGADD` after every other, `OP_M ‖ terminator`
    (R-MS-7's `TAPSCRIPT_NUMEQUAL` byte; `OP_CHECKMULTISIG` is a
    rejection) terminus, no trailing bytes, and no duplicate keys.
    Anything else raises `InvalidMultisigTapscript`."""
    from yubtc.fwd import MS_MAX_PUBKEYS
    script = bytes(script)
    # The minimal canonical script is 1-of-1: 36 bytes.
    if len(script) < 34 + 2:
        raise InvalidMultisigTapscript()
    # The fixed 2-byte tail: OP_M ‖ terminator.
    m_op = script[len(script) - 2]
    if script[len(script) - 1] != TAPSCRIPT_NUMEQUAL \
            or not (0x51 <= m_op <= 0x5f):
        raise InvalidMultisigTapscript()
    m = m_op - 0x50
    # The body must decompose into an exact number of 34-byte
    # (0x20 ‖ 32) key slots -- a trailing fragment or an
    # OP_PUSHDATA-wrapped key shifts the frame and fails here.
    body = len(script) - 2
    if body % 34 != 0:
        raise InvalidMultisigTapscript()
    n = body // 34
    if m > n or n > MS_MAX_PUBKEYS:
        raise InvalidMultisigTapscript()
    keys = []
    for i in range(n):
        start = i * 34
        if script[start] != 0x20:
            raise InvalidMultisigTapscript()
        keys.append(script[start + 1:start + 33])
        opcode = script[start + 33]
        expected = OP_CHECKSIG if i == 0 else OP_CHECKSIGADD
        if opcode != expected:
            raise InvalidMultisigTapscript()
    # R-MS-3 carried over: duplicates make the quorum degenerate.
    if len(set(keys)) != len(keys):
        raise InvalidMultisigTapscript()
    return m, keys


@require_kwargs_only
def tapscript_leaf_hash(script: bytes = NotNone) -> bytes:
    """BIP-341 `hashTapLeaf` of a tapscript (the single-leaf Merkle
    root): `tagged_hash("TapLeaf", 0xc0 ‖ compact_size(|script|) ‖
    script)` (mirrors `script.rs::tapscript_leaf_hash`).

    There is deliberately **no** `0x00` prefix before the leaf
    version: the BIP-341 definition commits to `leaf_version ‖
    compact_size ‖ script` directly, and the `compact_size` is the
    minimal length encoding (512 → `fd 00 02`), never an
    `OP_PUSHDATA` push."""
    from yubtc.hash import tagged_hash
    from yubtc.transaction import compact_size
    script = bytes(script)
    msg = (bytes([TAPSCRIPT_LEAF_VERSION])
           + compact_size(len(script)) + script)
    return tagged_hash(b'TapLeaf', msg)


@require_kwargs_only
def make_multisig_tapscript_witness(script: bytes = NotNone,
                                    control_block: bytes = NotNone,
                                    sig_slots: list = NotNone) -> list:
    """Assemble the finalized **P2TR script-path** witness stack
    (v0.3, spec.md R-MS-11; mirrors
    `script.rs::make_multisig_tapscript_witness`):

    ```
    [w_N, …, w_1] ‖ tapscript ‖ control_block
    ```

    `sig_slots` is indexed in **script-key order** (`w_1` first):
    each slot is a 64-byte Schnorr signature (`SIGHASH_DEFAULT`, no
    sighash byte -- ОВ-17) for a signer or ``None`` for a
    non-signer -- the assembler reverses the slots because BIP-342
    fixes the witness as `<w_n> … <w_1>` (the stack must present
    `pk_i` on top of its signature at execution time). There is **no**
    dummy element: `OP_CHECKSIGADD` has no off-by-one stack error, so
    the R-MS-5 dummy of the CHECKMULTISIG forms does not exist here.
    The `N + 2`-item stack is valid as long as exactly `M` slots are
    signatures; enforcing the count is the Finalizer's job, not the
    assembler's. Returns the stack as a list of `bytes` items."""
    script = bytes(script)
    control_block = bytes(control_block)
    out = [bytes(slot) if slot is not None else b''
           for slot in reversed(sig_slots)]
    out.append(script)
    out.append(control_block)
    return out


@require_kwargs_only
def redeem2taproot_addr(script: bytes = NotNone) -> str:
    """Tapscript leaf -> mainnet P2TR quorum address (`bc1p...`,
    bech32m witness version 1 with the 32-byte tweaked NUMS output
    key; v0.3, mirrors `address.rs::redeem_to_tapscript_address`).

    The commitment is `Q = lift_x(H) + t·G` over the NUMS internal
    key `H` (`yubtc.fwd.MS_TAPSCRIPT_INTERNAL_KEY`) and the leaf's
    `hashTapLeaf` -- the same 32-byte value
    `make_p2tr_lock_script` embeds in the lock script, so an output
    paid to the returned address is spendable exactly by revealing
    the tapscript and the control block in the witness (the v0.3
    quorum address of the `p2tr` form; ОВ-13 -- fixed by the
    `(N, M, keys)` tuple, no scan/gap walk).

    Errors: `TapTweakError` from the output-key derivation (only when
    the internal key is not a curve point or the tweak scalar hits
    the ~2^-128 `t ≥ n` case -- unreachable for the canonical NUMS
    key)."""
    from yubtc.bech32 import BECH32M, bytes_to_5bit, encode
    from yubtc.crypto import HRP_MAINNET, tapscript_output_key
    from yubtc.fwd import MS_TAPSCRIPT_INTERNAL_KEY
    leaf_hash = tapscript_leaf_hash(script=script)
    output_key = tapscript_output_key(internal_xonly=MS_TAPSCRIPT_INTERNAL_KEY,
                                      leaf_hash=leaf_hash)
    data = bytes([1]) + bytes_to_5bit(data=output_key)
    return encode(hrp=HRP_MAINNET, encoding=BECH32M, data=data)
