import decimal
from decimal import Decimal


class TBTC(Decimal):
    """BTC amount: a Decimal subclass with a friendlier parse error.

    The CLI converts user-supplied strings ("0.5", "1.234", or, through
    typos, "abc" or "") to `TBTC` via the click `type=TBTC` option and
    the `TBTC(amount)` call in `send`. `Decimal`'s default behaviour for
    unparseable input is to raise `decimal.InvalidOperation`, which is
    tedious to catch generically (the surrounding code may not import
    `decimal` at all). `ValueError` is the standard Python idiom for
    invalid input and `click` already wraps it in `BadParameter`, so
    the CLI shows a useful "Invalid value" message.

    All other Decimal behaviour -- arithmetic, the (sign, digits, exp)
    tuple form, `Decimal(...)` interop -- is unchanged.
    """
    def __new__(cls, value='0'):
        try:
            return super().__new__(cls, value)
        except decimal.InvalidOperation as e:
            raise ValueError(
                'not a valid BTC amount: {value!r}'.format(value=value)) from e


TSeed = str
TAddress = str
TAmount = str
TSatoshi = int
TNonce = int
# Passphrase is a string; the empty string means "no passphrase" and
# triggers the legacy KDF path. This alias exists for symmetry with the
# other type aliases in this module and to make the KDF signature
# self-documenting at call sites.
TPassphrase = str

# Defaults for function signatures. Centralised so callers can override one
# place and have every signature pick up the change.
DEFAULT_NONCE: TNonce = 0
DEFAULT_LOCKTIME: int = 0
DEFAULT_SEED_WORDS: int = 15
DEFAULT_ALLOW_DUPS: bool = True
DEFAULT_NEW_ADDRESSES: int = 1
DEFAULT_FEE: TBTC = TBTC(0)
# Default passphrase: empty string means "no passphrase", which makes
# `seed2bin` skip PBKDF2 entirely and stay bit-for-bit identical with
# the pre-passphrase behaviour. Callers who want to opt in pass a
# non-empty value through the prompt; the `get_passphrase()` helper in
# `seed.py` is the only way the CLI does that today.
DEFAULT_PASSPHRASE: str = ''
# Sequence value used by CIn when caller doesn't pass one. 0xffffffff marks
# the input as final (no replacement/RBF).
SEQUENCE_FINAL: int = 0xffffffff
# Empty script (the CScript constructor's default value).
EMPTY_SCRIPT: bytes = b''

MINIMAL_FEE: TSatoshi = 2000
# Minimum relay feerate (sat/kvB) enforced by the fee loop: a candidate
# whose fee is below size * MIN_RELAY_TX_FEE / 1000 would be rejected by
# every mempool. Source: Bitcoin Core policy.h DEFAULT_MIN_RELAY_TX_FEE;
# the Rust port reads the same number from
# bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE (decision C2).
MIN_RELAY_TX_FEE: int = 1000
# Confirmation count the CLI requires before considering a UTXO spendable.
DEFAULT_CONFIRMATIONS: int = 6
# HTTP request timeout for blockchain.info calls (seconds). Deliberately
# short (decision C4): backends must answer fast, and a long timeout masks
# a hung backend as a "slow wallet" instead of surfacing the network
# error to the user.
DEFAULT_TIMEOUT_HTTP: int = 5


class AddrType(object):
    """Address type selector (mirrors `yubtc core` Phase 13
    `AddrType { Legacy, Native, Taproot }`; the values are the
    `--addr-type` CLI names).

    - `LEGACY`: mainnet P2PKH (`1...`), the v0.1 behaviour.
    - `NATIVE`: native SegWit P2WPKH (`bc1q...`, BIP-84 for the
      pbkdf2 KDF).
    - `TAPROOT`: P2TR key-path (`bc1p...`, BIP-86 for the pbkdf2 KDF).
    """

    LEGACY = 'legacy'
    NATIVE = 'native'
    TAPROOT = 'taproot'


# All valid AddrType values, in registration order.
ADDR_TYPES = (AddrType.LEGACY, AddrType.NATIVE, AddrType.TAPROOT)

# Default address type after Phase 13 (spec ОВ-1): Native (P2WPKH);
# Taproot stays opt-in. Mirrors `fwd.rs::DEFAULT_ADDR_TYPE`.
DEFAULT_ADDR_TYPE: str = AddrType.NATIVE

# Dust thresholds (satoshi), per Bitcoin Core `GetDustThreshold` with
# dustRelayFee = 3 sat/kvB and the spend weight of the canonical
# spending input (witness forms 67 vB, legacy 148 vB). Mirrors the
# Phase 13 `fwd.rs` constants.
DUST_THRESHOLD_P2PKH: int = 546
DUST_THRESHOLD_P2SH: int = 540
DUST_THRESHOLD_P2WPKH: int = 294
DUST_THRESHOLD_P2TR: int = 330

# --- PSBT (BIP-174, Phase 14) -----------------------------------------
# Frozen snapshot of the Phase 14 spec values (mirrors `fwd.rs`); see
# spec.md «PSBT — BIP-174» and `psbt.py`.

# Hard cap on the encoded size of a PSBT (bytes). A parse attempt on a
# bigger blob fails with `PsbtTooLarge` before any allocation (fuzz/OOM
# guard against allocation bombs through 64-bit compact sizes).
PSBT_MAX_SIZE: int = 4 * 1024 * 1024

# The Signer walk (ОВ-9): a stateless wallet has no UTXO->key map, so
# "own" inputs are found by a bounded offline walk over nonces
# `0..PSBT_SIGN_MAX_NONCE`, deriving all three address forms per nonce.
# Inputs keyed beyond the bound stay unsigned and are reported back.
PSBT_SIGN_MAX_NONCE: int = 1000

# Sighash flags the signer produces or accepts for these forms; a PSBT
# whose `SIGHASH_TYPE` field disagrees leaves the input unsigned (ОВ-8).
PSBT_SIGHASH_ALL: int = 0x0000_0001
PSBT_SIGHASH_DEFAULT: int = 0x0000_0000

# --- Multi-sig (P2SH, Phase 15) -----------------------------------------
# Frozen snapshot of the Phase 15 spec values (mirrors `fwd.rs`); see
# spec.md «Multi-sig (P2SH)» and `script.py` / `wallet.py`.

# Maximum keys in a CHECKMULTISIG quorum (R-MS-2): `1 ≤ M ≤ N ≤ 15`.
# 15, not the consensus 20-key cap: an N = 16 redeem script is
# 34·16 + 4 = 548 bytes > the 520-byte MAX_SCRIPT_ELEMENT_SIZE push
# limit, so such a P2SH output is fundamentally unspendable.
MS_MAX_PUBKEYS: int = 15
