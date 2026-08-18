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
