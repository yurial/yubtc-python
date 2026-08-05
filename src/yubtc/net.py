"""Network I/O used by the wallet.

The wallet talks to a `NetworkBackend`, not to a specific HTTP API.
`BlockchainInfoBackend` is the default: it hits blockchain.info's
unspent / balance / pushtx endpoints directly.

The module-level free functions `get_address_info`,
`get_address_unspent`, `broadcastTx` are the public entry point: each one
resolves the current backend via `get_current_backend()` and calls
its method. They exist so callers (and tests) have a single, stable
function name to call or patch.

Swap the current backend with `set_current_backend(backend)` -- e.g.
a custom subclass for alternative API providers, or a no-op test
backend defined in the test suite. `reset_backend()` restores the
default.
"""
from yubtc.fwd import TAddress, DEFAULT_TIMEOUT_HTTP


class NetworkBackend:
    """Pluggable network I/O for the wallet.

    Concrete backends override the three methods below. The default
    kwargs catch-all lets callers (and tests) pass extra parameters
    without a signature churn -- the current wallet never uses them,
    but external backends can.
    """

    def get_unspent(self, address: TAddress, **kwargs) -> list:
        """Return the list of UTXOs for `address`.

        The wallet reshapes each entry, so the return shape mirrors
        blockchain.info's unspent endpoint: a list of dicts with
        'tx_hash', 'tx_output_n', 'value', 'script' (and other fields
        the wallet ignores).
        """
        raise NotImplementedError

    def get_info(self, address: TAddress, **kwargs) -> dict:
        """Return the address's balance info.

        The wallet reads 'total_received' to detect an unused address.
        """
        raise NotImplementedError

    def send_tx(self, rawtx: bytes, **kwargs) -> None:
        """Broadcast a signed raw transaction. Raise on failure."""
        raise NotImplementedError


class BlockchainInfoBackend(NetworkBackend):
    """Default backend: hits blockchain.info's public API."""

    def get_unspent(self, address: TAddress, **kwargs) -> list:
        import requests
        from json.decoder import JSONDecodeError
        try:
            url = 'https://blockchain.info/unspent?active={address}'.format(
                address=address.decode('ascii'))
            return requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP).json()['unspent_outputs']
        except JSONDecodeError:
            return []

    def get_info(self, address: TAddress, **kwargs) -> dict:
        import requests
        from json.decoder import JSONDecodeError
        address_str = address.decode('ascii')
        try:
            url = 'https://blockchain.info/balance?active={address}'.format(address=address_str)
            response = requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP)
            return response.json()[address_str]
        except JSONDecodeError:
            return {'total_received': 0}

    def send_tx(self, rawtx: bytes, **kwargs) -> None:
        """Broadcast a signed raw transaction via blockchain.info/pushtx.

        The endpoint accepts the raw tx hex as a form-encoded `tx` field
        and returns 200 with body "Transaction Submitted" on success.
        Any non-2xx response is treated as a failure (the wallet has
        already printed the tx id, so surfacing the error is the right
        move).
        """
        import requests
        url = 'https://blockchain.info/pushtx'
        response = requests.post(url, data={'tx': rawtx.hex()}, timeout=DEFAULT_TIMEOUT_HTTP)
        if not response.ok:
            raise RuntimeError(
                'broadcast failed: status={status} body={body}'.format(
                    status=response.status_code, body=response.text))


_current_backend = BlockchainInfoBackend()


def get_current_backend() -> NetworkBackend:
    """Return the backend used by wallet/TPrivKey network calls.

    `set_current_backend(backend)` swaps this; `reset_backend()`
    restores the `BlockchainInfoBackend` default.
    """
    return _current_backend


def set_current_backend(backend: NetworkBackend) -> None:
    """Replace the backend used by subsequent wallet network calls.

    `get_current_backend()` returns the new backend from the next
    lookup. Pair with `reset_backend()` to undo the change.
    """
    global _current_backend
    _current_backend = backend


def reset_backend() -> None:
    """Restore the default `BlockchainInfoBackend`."""
    global _current_backend
    _current_backend = BlockchainInfoBackend()


# ---------------------------------------------------------------------------
# Module-level free functions: the public entry point.
#
# Each function resolves the current backend and calls its method. The
# test suite can intercept at either layer: by monkeypatching the
# free function itself, or by swapping the backend via
# `set_current_backend`.
# ---------------------------------------------------------------------------

def get_address_unspent(address: TAddress) -> list:
    """Return the UTXOs for `address` via the current backend."""
    return get_current_backend().get_unspent(address)


def get_address_info(address: TAddress) -> dict:
    """Return the address's balance info via the current backend."""
    return get_current_backend().get_info(address)


def broadcastTx(rawtx: bytes) -> None:
    """Broadcast a signed raw transaction via the current backend."""
    get_current_backend().send_tx(rawtx)
