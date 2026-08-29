"""Bitcoin transaction model, signing, and SegWit witness support.

Legacy (pre-SegWit) model mirrors the original yubtc behaviour
byte-for-byte: `CIn`/`COut`/`CTransaction` with `struct.pack`, the
LEB128 `toVarInt`, and the SIGHASH_ALL blanked-serialization preimage.

Phase 13 (SegWit/Taproot, mirrors `yubtc core/src/transaction.rs`):

- `CIn` carries a witness stack (empty for legacy inputs; all v0.1
  constructors keep producing empty stacks).
- Serialization splits into `serialize_stripped` (the v0.1 layout,
  witness ignored -- what `txid` hashes) and `serialize_wire`
  (marker/flag + witness stacks -- what `wtxid` hashes and what goes
  on the network when any input is witnessed). For transactions
  without witness the two are byte-identical, so every v0.1
  transaction serializes exactly as before.
- `weight`/`vsize` implement the BIP-141 fee accounting.
- Signing: `sign()` stays the legacy-everything path;
  `sign_segwit()` dispatches per input on the shape of the UTXO
  `scriptPubKey` (the build_vin convention: `CIn.script` holds the
  UTXO lock script until signing) -- legacy inputs get the unchanged
  SIGHASH_ALL scriptSig, P2WPKH inputs a BIP-143 SIGHASH_ALL witness,
  P2TR key-path inputs a BIP-341 SIGHASH_DEFAULT Schnorr witness.

Schnorr primitive: `coincurve.PrivateKey.sign_schnorr` (libsecp256k1's
BIP-340 `secp256k1_schnorrsig_sign32`) with the deterministic
`aux_rand = 0x00 * 32` (spec ОВ-3). BIP-340 signing is fully
deterministic given (key, message, aux), so this is bit-for-bit
identical to the Rust port's k256 Schnorr -- pinned by the official
BIP-341 signature test vector.
"""
from typing import NamedTuple
from copy import deepcopy

from yubtc.util import NotNone, OPTIONAL, require_kwargs_only

_MSG_MISSING_SPEND_CONTEXT = ('spend context missing or incomplete '
                              '(BIP-143/BIP-341 signing needs amounts and '
                              'scriptPubKeys of all inputs)')


def script2pkh(script: bytes) -> bytes:
    from yubtc.script import OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
    if (len(script) != 25
        or script[0] != OP_DUP
        or script[1] != OP_HASH160
        or script[2] != 20
        or script[-2] != OP_EQUALVERIFY
            or script[-1] != OP_CHECKSIG):
        raise ValueError('invalid script')
    return script[3:-2]


def toVarInt(value: int) -> bytes:
    """Pack `value` into varint bytes"""
    from struct import pack
    if value < 0:
        raise ValueError('toVarInt value must be non-negative')
    buf = b''
    while True:
        towrite = value & 0x7f
        value >>= 7
        if value:
            buf += pack(b'B', towrite | 0x80)
        else:
            buf += pack(b'B', towrite)
            break
    return buf


def compact_size(n: int) -> bytes:
    """Bitcoin CompactSize wire encoding (`0xfd`/`0xfe`/`0xff` prefixes).

    Used for witness item counts and lengths (mirrors
    `transaction.rs::compact_size`). The legacy vin/vout layout keeps
    `toVarInt` (LEB128): the two encodings coincide below 0xfd, which
    covers every value the wallet serializes -- counts and
    script/witness lengths alike."""
    from struct import pack
    if n < 0:
        raise ValueError('compact_size value must be non-negative')
    if n < 0xfd:
        return pack(b'<B', n)
    if n <= 0xffff:
        return pack(b'<cH', b'\xfd', n)
    if n <= 0xffffffff:
        return pack(b'<cL', b'\xfe', n)
    return pack(b'<cQ', b'\xff', n)


# --- Signing schemes (Phase 13) ----------------------------------------

# How an input is signed, derived from the shape of the UTXO's
# `scriptPubKey` (mirrors `transaction.rs::SigScheme`).
SIG_SCHEME_LEGACY = 'legacy'
SIG_SCHEME_P2WPKH = 'bip143_p2wpkh'
SIG_SCHEME_P2TR = 'bip341_keypath'


@require_kwargs_only
def sig_scheme_from_script_pubkey(script_pubkey: bytes = NotNone) -> str:
    """Dispatch a `scriptPubKey` to its signing scheme by strict shape:
    `00 14 <20>` -> P2WPKH, `51 20 <32>` -> P2TR key-path, everything
    else (including P2PKH, P2SH and malformed look-alikes) -> legacy."""
    script_pubkey = bytes(script_pubkey)
    if (len(script_pubkey) == 22 and script_pubkey[0] == 0x00
            and script_pubkey[1] == 0x14):
        return SIG_SCHEME_P2WPKH
    if (len(script_pubkey) == 34 and script_pubkey[0] == 0x51
            and script_pubkey[1] == 0x20):
        return SIG_SCHEME_P2TR
    return SIG_SCHEME_LEGACY


class SpendInput(NamedTuple):
    """UTXO metadata for one input (mirrors
    `transaction.rs::SpendInput`). Committed by both the BIP-143 and
    the BIP-341 digests; `spend` lists must be parallel to `vin`."""
    amount: int
    script_pubkey: bytes


# Per-input UTXO metadata required by the SegWit digest algorithms
# (mirrors `transaction.rs::SpendContext`): one `SpendInput` per
# transaction input, in `vin` order. BIP-143 commits to the signed
# input's amount; BIP-341 commits to the amounts and scriptPubKeys of
# every input. Legacy-only transactions never consult the context.
SpendContext = list

_SIGHASH_ALL = 0x01
_SIGHASH_ALL_LE = b'\x01\x00\x00\x00'
# SIGHASH_DEFAULT hash-type byte for the BIP-341 SigMsg (semantically
# equal to SIGHASH_ALL; the Schnorr signature carries no sighash
# suffix, so the witness item is exactly 64 bytes).
_SIGHASH_DEFAULT = 0x00


def dsha256(data: bytes) -> bytes:
    """Double SHA-256, in internal (non-reversed) byte order."""
    from yubtc.hash import sha256
    return sha256(sha256(data))


class CIn(object):
    @require_kwargs_only
    def __init__(self, txhash: bytes = NotNone, n: int = NotNone,
                 script: bytes = b'', sequence: int = NotNone,
                 witness: list = OPTIONAL):
        if len(txhash) != 32:
            raise ValueError('txhash should be 32 bytes length')
        if n < 0:
            raise ValueError('n should be non-negative')
        if n > 0xffffffff:
            raise ValueError('n should be less or equal than 0xffffffff')
        if sequence < 0:
            raise ValueError('sequence should be non-negative')
        if sequence > 0xffffffff:
            raise ValueError('sequence should be less or equal than 0xffffffff')
        self.txhash = bytes(txhash)
        self.n = n
        self.script = script
        self.sequence = sequence
        # Witness stack (BIP-141): empty for legacy and unsigned SegWit
        # inputs (the OPTIONAL default keeps every v0.1 constructor
        # byte-compatible). After `sign_segwit` a P2WPKH input carries
        # `(DER sig || 0x01, compressed pubkey)` and a P2TR key-path
        # input a bare 64-byte Schnorr signature. The stack is
        # excluded from the stripped serialization and the txid, but
        # included in the wire serialization and the wtxid.
        if witness is OPTIONAL:
            witness = ()
        self.witness = tuple(bytes(item) for item in witness)

    def serialize(self) -> bytes:
        """
        32  hash                char[32]    The hash of the referenced transaction.
        4   index               uint32_t    The index of the specific output in the transaction.
                                             The first output is 0, etc.
        1+  script length       var_int     The length of the signature script
        ?   signature script    uchar[]     Computational Script for confirming transaction authorization
        4   sequence            uint32_t    Transaction version as defined by the sender. Intended
                                             for "replacement" of transactions when information is
                                             updated before inclusion into a block.
        """
        from struct import pack
        result = self.txhash
        result += pack(b"<L", self.n)
        result += toVarInt(len(self.script))
        result += self.script
        result += pack(b"<L", self.sequence)
        return result


class COut(object):
    @require_kwargs_only
    def __init__(self, amount: int = NotNone, script: bytes = b''):
        if amount < 0:
            raise ValueError('amount should be non-negative')
        if amount > 0xffffffffffffffff:
            raise ValueError('amount should be less or equal than 0xffffffffffffffff')
        self.amount = amount
        self.script = script

    def serialize(self) -> bytes:
        """
        8   value               int64_t     Transaction Value
        1+  pk_script length    var_int     Length of the pk_script
        ?   pk_script           uchar[]     Usually contains the public key as a Bitcoin script
                                             setting up conditions to claim this output.
        """
        from struct import pack
        result = pack(b"<Q", self.amount)
        result += toVarInt(len(self.script))
        result += self.script
        return result


class CTransaction(object):
    @require_kwargs_only
    def __init__(self, vin: list = NotNone, vout: list = NotNone,
                 locktime: int = NotNone):
        self.version = 2
        self.vin = vin
        self.vout = vout
        self.locktime = locktime

    def serialize_stripped(self) -> bytes:
        """
        4       version         int32_t     Transaction data format version (note, this is signed)
        1+      tx_in count     var_int     Number of Transaction inputs
        41+     tx_in           tx_in[]     A list of 1 or more transaction inputs
        1+      tx_out count    var_int     Number of Transaction outputs
        9+      tx_out          tx_out[]    A list of 1 or more transaction outputs
        4       lock_time       uint32_t    The block number or timestamp at which this transaction is unlocked.

        Serialise the **stripped** (pre-SegWit) layout. Witness stacks
        are ignored; `id()` is the double-SHA256 of exactly these
        bytes (BIP-141). This IS the v0.1 `serialize` layout -- kept
        bit-for-bit.
        """
        from struct import pack
        result = pack(b"<l", self.version)
        result += toVarInt(len(self.vin))
        for i in self.vin:
            result += i.serialize()
        result += toVarInt(len(self.vout))
        for o in self.vout:
            result += o.serialize()
        result += pack(b"<L", self.locktime)
        return result

    def serialize(self) -> bytes:
        """Serialise the full transaction in the stripped layout.

        Kept as the v0.1 entry point so existing callers (fee loop
        sizing, broadcast hex) stay byte-for-byte; SegWit-aware
        serialization is `serialize_wire`."""
        return self.serialize_stripped()

    def has_witness(self) -> bool:
        """True when at least one input carries a non-empty witness
        stack."""
        return any(vin.witness for vin in self.vin)

    def serialize_wire(self) -> bytes:
        """Serialise the **wire** layout (BIP-144):

        4 version (LE) || `0x00 0x01` (marker+flag, only when
        witnessed) || vin || vout || witness stacks || locktime (LE).

        When no input carries a witness the marker/flag section is
        omitted and the output is byte-identical to
        `serialize_stripped` -- every v0.1 transaction serializes
        exactly as before."""
        if not self.has_witness():
            return self.serialize_stripped()
        from struct import pack
        result = pack(b"<l", self.version)
        result += b'\x00\x01'  # marker || flag
        result += toVarInt(len(self.vin))
        for i in self.vin:
            result += i.serialize()
        result += toVarInt(len(self.vout))
        for o in self.vout:
            result += o.serialize()
        for i in self.vin:
            result += compact_size(len(i.witness))
            for item in i.witness:
                result += compact_size(len(item)) + item
        result += pack(b"<L", self.locktime)
        return result

    def weight(self) -> int:
        """Transaction weight (BIP-141): `base_size*3 + total_size`,
        where base is the stripped and total the wire size."""
        return len(self.serialize_stripped()) * 3 + len(self.serialize_wire())

    def vsize(self) -> int:
        """Virtual size (BIP-141): `ceil(weight / 4)`. Equals the
        stripped size for transactions without witness, so the v0.1
        fee math is unchanged."""
        return -(-self.weight() // 4)

    @require_kwargs_only
    def sign(self, signers: list = NotNone) -> 'CTransaction':
        """Produce a signed copy of the transaction (legacy path).

        `signers` is `[(privkey, pubkey)]` parallel to `vin`: one
        `(privkey, compressed pubkey)` per input. Each input's
        signature script ends up `<DER signature> <0x01 sighash byte>
        <33-byte pubkey>`, signed with the pre-SegWit SIGHASH_ALL
        algorithm, unchanged from v0.1. Transactions containing SegWit
        inputs must use `sign_segwit`, which dispatches per-input
        schemes."""
        if len(signers) != len(self.vin):
            raise ValueError('signers length must match vin length')
        tx = deepcopy(self)
        for i in range(len(tx.vin)):
            k, w = signers[i]
            tx.vin[i].script = self._legacy_script_sig(i, k, w)
        return tx

    def _legacy_script_sig(self, i: int, privkey, pubkey) -> bytes:
        """Legacy pre-SegWit SIGHASH_ALL signature script for input `i`.

        Shared by `sign` and `sign_segwit`: builds the blanked
        preimage (every `scriptSig` emptied except the signed input,
        which keeps its UTXO `scriptPubKey` per the build_vin
        convention), appends the sighash type, and returns
        `<DER sig> <0x01> <pubkey>`."""
        from yubtc.crypto import sign_data
        from yubtc.script import CScript
        from struct import pack
        tx = deepcopy(self)
        for z in range(len(tx.vin)):
            tx.vin[z].script = b''
        tx.vin[i] = deepcopy(self.vin[i])
        sigdata = tx.serialize() + pack(b'<L', _SIGHASH_ALL)
        signature = sign_data(privkey=privkey, data=sigdata) + pack(b'<B', _SIGHASH_ALL)
        return CScript([signature, pubkey])

    @require_kwargs_only
    def sign_segwit(self, signers: list = NotNone,
                    spend: list = OPTIONAL) -> 'CTransaction':
        """Produce a signed copy of the transaction, choosing each
        input's scheme from its UTXO `scriptPubKey` shape
        (`sig_scheme_from_script_pubkey`).

        - Legacy inputs get the pre-SegWit SIGHASH_ALL `scriptSig`
          (byte-for-byte the `sign` output).
        - P2WPKH inputs get a BIP-143 SIGHASH_ALL signature as the
          witness `(DER sig || 0x01, compressed pubkey)`; `scriptSig`
          is emptied.
        - P2TR key-path inputs get a BIP-341 SIGHASH_DEFAULT digest
          signed with BIP-340 Schnorr (`aux_rand = 0x00 * 32`, spec
          ОВ-3) as a bare 64-byte witness item; `scriptSig` is emptied.

        Mixed transactions (legacy + witness inputs) are allowed: each
        input's digest is computed independently.

        `spend` is the `SpendContext` -- one `SpendInput` per input,
        parallel to `vin`. BIP-143 needs the signed input's amount;
        BIP-341 needs the amounts and scriptPubKeys of *all* inputs.
        Omitting it is fine for legacy-only transactions; a SegWit
        input without it raises `ValueError` (mirrors
        `TransactionError::MissingSpendContext`).
        """
        if len(signers) != len(self.vin):
            raise ValueError('signers length must match vin length')
        ctx = None if spend is OPTIONAL else spend
        tx = deepcopy(self)
        for i in range(len(tx.vin)):
            k, w = signers[i]
            scheme = sig_scheme_from_script_pubkey(script_pubkey=self.vin[i].script)
            if scheme == SIG_SCHEME_LEGACY:
                tx.vin[i].script = self._legacy_script_sig(i, k, w)
            elif scheme == SIG_SCHEME_P2WPKH:
                meta = _spend_input(ctx, i)
                script_code = p2wpkh_script_code(script_pubkey=self.vin[i].script)
                sighash = _bip143_sighash_in_range(tx, i, script_code, meta.amount)
                from yubtc.crypto import sign_hash
                witness_sig = sign_hash(privkey=k, datahash=sighash) + bytes([_SIGHASH_ALL])
                tx.vin[i].script = b''
                tx.vin[i].witness = (witness_sig, bytes(w))
            else:  # SIG_SCHEME_P2TR
                if ctx is None or len(ctx) != len(tx.vin):
                    raise ValueError(_MSG_MISSING_SPEND_CONTEXT)
                sighash = _taproot_keypath_sighash_in_range(tx, i, ctx)
                tx.vin[i].script = b''
                tx.vin[i].witness = (taproot_sign_sighash(privkey=k, sighash=sighash),)
        return tx

    def id(self) -> bytes:
        """Bitcoin transaction id: the double-SHA256 of the **stripped**
        serialization, displayed in the reversed (LE) order expected by
        block explorers. Witness data does not affect the txid
        (BIP-141); for legacy transactions this is the same value v0.1
        produced."""
        return dsha256(self.serialize_stripped())[::-1]

    def wtxid(self) -> bytes:
        """Witness transaction id (BIP-141): double-SHA256 of the
        **wire** serialization, in the same reversed display order as
        `id`. For transactions without witness this equals the txid
        (the wire layout is the stripped one)."""
        return dsha256(self.serialize_wire())[::-1]


def _spend_input(ctx, i: int) -> SpendInput:
    """Fetch input `i`'s UTXO metadata, refusing short or absent
    contexts (mirrors the `ok_or(MissingSpendContext)` lookups in
    `transaction.rs::sign_segwit`)."""
    if ctx is None:
        raise ValueError(_MSG_MISSING_SPEND_CONTEXT)
    try:
        return ctx[i]
    except IndexError:
        raise ValueError(_MSG_MISSING_SPEND_CONTEXT)


def p2wpkh_script_code(script_pubkey: bytes) -> bytes:
    """P2WPKH `scriptCode` for BIP-143: `0x19 0x76 0xa9 0x14 <20-byte
    hash> 0x88 0xac` (26 bytes: the CompactSize length prefix plus the
    equivalent P2PKH script), rebuilt from the 22-byte `00 14 <hash>`
    witness program.

    Contract: `script_pubkey` must be the 22-byte P2WPKH shape
    (guaranteed by `sig_scheme_from_script_pubkey` dispatch)."""
    return (b'\x19\x76\xa9\x14' + bytes(script_pubkey[2:22])
            + b'\x88\xac')


@require_kwargs_only
def bip143_sighash(tx: 'CTransaction' = NotNone, input_index: int = NotNone,
                   script_code: bytes = NotNone, amount: int = NotNone) -> bytes:
    """BIP-143 signature digest (SIGHASH_ALL) for a P2WPKH input.

    `script_code` is the 26-byte `0x1976a914{hash}88ac` blob
    (`p2wpkh_script_code`); `amount` the spent output's value in
    satoshi. All other committed data comes from `tx` (version,
    outpoints, sequences, outputs, locktime).

    Raises `ValueError` when `input_index` is not a valid input of
    `tx` (mirrors `TransactionError::InputIndexOutOfRange`)."""
    if input_index >= len(tx.vin):
        raise ValueError(f'input index {input_index} out of range ({len(tx.vin)} inputs)')
    return _bip143_sighash_in_range(tx, input_index, script_code, amount)


def _bip143_sighash_in_range(tx: 'CTransaction', input_index: int,
                             script_code: bytes, amount: int) -> bytes:
    """Core of `bip143_sighash` without the index validation.

    Contract: `input_index < len(tx.vin)` -- checked by the public
    wrapper and guaranteed inside `sign_segwit` by the signing loop."""
    from struct import pack
    vin = tx.vin[input_index]

    buf = b''.join(i.txhash + pack(b'<L', i.n) for i in tx.vin)
    hash_prevouts = dsha256(buf)

    buf = b''.join(pack(b'<L', i.sequence) for i in tx.vin)
    hash_sequence = dsha256(buf)

    buf = b''.join(o.serialize() for o in tx.vout)
    hash_outputs = dsha256(buf)

    preimage = (pack(b'<l', tx.version)
                + hash_prevouts
                + hash_sequence
                + vin.txhash
                + pack(b'<L', vin.n)
                + script_code
                + pack(b'<Q', amount)
                + pack(b'<L', vin.sequence)
                + hash_outputs
                + pack(b'<L', tx.locktime)
                + _SIGHASH_ALL_LE)
    return dsha256(preimage)


@require_kwargs_only
def taproot_keypath_sighash(tx: 'CTransaction' = NotNone,
                            input_index: int = NotNone,
                            spend: list = NotNone) -> bytes:
    """BIP-341 signature digest for a P2TR **key-path** spend with
    `SIGHASH_DEFAULT` (0x00) and no annex.

    `spend` must carry one `SpendInput` per transaction input --
    BIP-341 commits to the amounts and scriptPubKeys of *all* inputs;
    the context's `script_pubkey` values are authoritative for the
    digest.

    Raises `ValueError` when the context does not cover every input
    (missing spend context) or when `input_index` is invalid."""
    if len(spend) != len(tx.vin):
        raise ValueError(_MSG_MISSING_SPEND_CONTEXT)
    if input_index >= len(tx.vin):
        raise ValueError(f'input index {input_index} out of range ({len(tx.vin)} inputs)')
    return _taproot_keypath_sighash_in_range(tx, input_index, spend)


def _taproot_keypath_sighash_in_range(tx: 'CTransaction', input_index: int,
                                      spend: list) -> bytes:
    """Core of `taproot_keypath_sighash` without the context/index
    validation.

    Contract: `len(spend) == len(tx.vin)` and
    `input_index < len(tx.vin)` -- both checked by the public wrapper
    and guaranteed inside `sign_segwit`."""
    from struct import pack
    from yubtc.hash import sha256, tagged_hash

    buf = b''.join(i.txhash + pack(b'<L', i.n) for i in tx.vin)
    sha_prevouts = sha256(buf)

    buf = b''.join(pack(b'<Q', meta.amount) for meta in spend)
    sha_amounts = sha256(buf)

    buf = b''.join(compact_size(len(meta.script_pubkey)) + meta.script_pubkey
                   for meta in spend)
    sha_scriptpubkeys = sha256(buf)

    buf = b''.join(pack(b'<L', i.sequence) for i in tx.vin)
    sha_sequences = sha256(buf)

    buf = b''.join(o.serialize() for o in tx.vout)
    sha_outputs = sha256(buf)

    # SigMsg = hash_type || nVersion || nLockTime || sha_prevouts
    #        || sha_amounts || sha_scriptpubkeys || sha_sequences
    #        || sha_outputs || spend_type || input_index.
    sig_msg = (bytes([_SIGHASH_DEFAULT])
               + pack(b'<l', tx.version)
               + pack(b'<L', tx.locktime)
               + sha_prevouts
               + sha_amounts
               + sha_scriptpubkeys
               + sha_sequences
               + sha_outputs
               + b'\x00'  # spend_type: ext_flag = 0 (key path), no annex
               + pack(b'<L', input_index))

    # sighash = tagged_hash("TapSighash", 0x00 (epoch) || SigMsg).
    return tagged_hash(b'TapSighash', b'\x00' + sig_msg)


@require_kwargs_only
def taproot_tweaked_scalar(privkey=NotNone) -> int:
    """Compute the BIP-86/BIP-341 tweaked signing scalar for a
    key-path spend with an empty Merkle root: `d' + t` where `d'` is
    the internal scalar normalized to the even-Y representation
    (`d' = d` for a 0x02 pubkey, `n - d` for 0x03) and
    `t = int(tagged_hash("TapTweak", x(P)))` with `x(P)` the parity-free
    x coordinate.

    The even-Y normalization is what BIP-341 defines the tweak over;
    without it an odd-y internal key would produce a signature
    verifying against a point other than the tweaked output key the
    address commits to. There is deliberately **no further** +/-t
    parity flip on Q: BIP-340 signing (which normalizes to the even-Y
    point internally -- both libsecp256k1 and k256 do) handles Q's
    parity; the x-only output key `x(Q)` is parity-independent.
    Mirrors `transaction.rs::taproot_tweaked_scalar` (whose
    "always matches output key" test pins the same invariant)."""
    from yubtc.bip32 import SECP256K1_N
    from yubtc.crypto import privkey2pubkey
    from yubtc.hash import tagged_hash
    pubkey = privkey2pubkey(privkey=privkey)
    xonly = pubkey[1:33]
    t = int.from_bytes(tagged_hash(b'TapTweak', xonly), 'big') % SECP256K1_N
    d = int.from_bytes(privkey.secret, 'big')
    if pubkey[0] == 0x03:
        # Odd-y internal key: normalize to the even-Y point first.
        d = SECP256K1_N - d
    return (d + t) % SECP256K1_N


@require_kwargs_only
def taproot_sign_sighash(privkey=NotNone, sighash: bytes = NotNone) -> bytes:
    """Sign a BIP-341 key-path sighash with BIP-340 Schnorr.

    The digest is signed under the **tweaked** key (see
    `taproot_tweaked_scalar`). `aux_rand` is the deterministic
    `0x00 * 32` (spec ОВ-3), so signatures are reproducible bit-for-bit
    across runs and against the Rust mirror. The primitive is
    `coincurve.PrivateKey.sign_schnorr` -- libsecp256k1's BIP-340
    signer, pinned byte-for-byte by the official BIP-341 signature
    test vector (identical to the Rust port's k256 signer because
    BIP-340 is deterministic).

    A zero tweaked scalar is unreachable for real keys (~2^-128) and
    is rejected outright by coincurve."""
    from coincurve import PrivateKey
    tweaked = taproot_tweaked_scalar(privkey=privkey)
    tweaked_key = PrivateKey(tweaked.to_bytes(32, 'big'))
    return tweaked_key.sign_schnorr(bytes(sighash), aux_randomness=b'\x00' * 32)
