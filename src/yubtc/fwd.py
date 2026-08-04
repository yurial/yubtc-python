from decimal import Decimal

TSeed = str
TAddress = str
TAmount = str
TSatoshi = int
TBTC = Decimal
TNonce = int

# Defaults for function signatures. Centralised so callers can override one
# place and have every signature pick up the change.
DEFAULT_NONCE: TNonce = 0
DEFAULT_COMPRESSED: bool = True
DEFAULT_LOCKTIME: int = 0
DEFAULT_SEED_WORDS: int = 15
DEFAULT_ALLOW_DUPS: bool = True
DEFAULT_NEW_ADDRESSES: int = 1
DEFAULT_FEE: TBTC = TBTC(0)
# Sequence value used by CIn when caller doesn't pass one. 0xffffffff marks
# the input as final (no replacement/RBF).
SEQUENCE_FINAL: int = 0xffffffff
# Empty script (the CScript constructor's default value).
EMPTY_SCRIPT: bytes = b''

MINIMAL_FEE: TSatoshi = 2000
DEFAULT_CONFIRMATIONS: int = 2
# CLI surface defaults -- distinct from `DEFAULT_CONFIRMATIONS` because the
# CLI shows a stricter confirmation count than the wallet's internal default.
DEFAULT_CLI_CONFIRMATIONS: int = 6
