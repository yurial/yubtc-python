"""Network I/O used by the wallet.

The wallet talks to a `NetworkBackend`, not to a specific HTTP API.
Three providers are wired up:
- `BlockchainInfoBackend`: blockchain.info's public API (default).
- `BlockstreamBackend`: blockstream.info's public Esplora API.
- `MempoolSpaceBackend`: mempool.space's public Esplora API.

The blockstream and mempool.space backends share an `EsploraBackend`
parent because both serve the same JSON schema; only the base URL
differs. Subclassing `BlockchainInfoBackend` with a custom `base_url`
is how an alternate mirror (e.g. behind a corporate firewall) is
wired up at runtime.

The module-level free functions `get_address_info`,
`get_address_unspent`, `broadcastTx` are the public entry point: each
one resolves the current backend via `get_current_backend()` and calls
its method. They exist so callers (and tests) have a single, stable
function name to call or patch.

Swap the current backend with `set_current_backend(backend)` -- e.g.
a custom subclass for alternative API providers, or a no-op test
backend defined in the test suite. `reset_backend()` restores the
default. Resolve a registered provider by name with
`get_backend(name=...)`; the registry is what powers the `--provider`
CLI flag.
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
        'tx_hash', 'tx_output_n', 'value', 'script', 'confirmations'
        (and other fields the wallet ignores).
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
    """Default backend: blockchain.info's public API.

    `base_url` overrides the default domain -- useful when the wallet
    runs behind a firewall that only allows a mirror. The endpoint
    paths (`/unspent`, `/balance`, `/pushtx`) are unchanged.
    """

    DEFAULT_BASE_URL: str = 'https://blockchain.info'

    def __init__(self, base_url: str = DEFAULT_BASE_URL) -> None:
        self._base_url = base_url

    def get_unspent(self, address: TAddress, **kwargs) -> list:
        import requests
        from json.decoder import JSONDecodeError
        url = '{base}/unspent?active={address}'.format(
            base=self._base_url, address=address.decode('ascii'))
        try:
            return requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP).json()['unspent_outputs']
        except JSONDecodeError:
            return []

    def get_info(self, address: TAddress, **kwargs) -> dict:
        import requests
        from json.decoder import JSONDecodeError
        address_str = address.decode('ascii')
        try:
            url = '{base}/balance?active={address}'.format(
                base=self._base_url, address=address_str)
            response = requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP)
            return response.json()[address_str]
        except JSONDecodeError:
            return {'total_received': 0}

    def send_tx(self, rawtx: bytes, **kwargs) -> None:
        """Broadcast a signed raw transaction via the pushtx endpoint.

        The endpoint accepts the raw tx hex as a form-encoded `tx` field
        and returns 200 with body "Transaction Submitted" on success.
        Any non-2xx response is treated as a failure (the wallet has
        already printed the tx id, so surfacing the error is the right
        move).
        """
        import requests
        url = '{base}/pushtx'.format(base=self._base_url)
        response = requests.post(url, data={'tx': rawtx.hex()},
                                 timeout=DEFAULT_TIMEOUT_HTTP)
        if not response.ok:
            raise RuntimeError(
                'broadcast failed: status={status} body={body}'.format(
                    status=response.status_code, body=response.text))


class EsploraBackend(NetworkBackend):
    """Esplora-style backend shared by blockstream.info and mempool.space.

    Both serve the same JSON schema, so the parent implements the full
    surface and subclasses just pin the base URL. The wallet-shaped
    UTXO (`tx_hash`, `tx_output_n`, `value`, `script`, `confirmations`)
    is reconstructed from the Esplora response: the UTXO endpoint does
    not echo the script, so it's rebuilt from the queried address via
    `make_lock_script`. Confirmations come from the difference between
    the UTXO's `block_height` and the chain tip (`/blocks/tip/height`).
    """

    def __init__(self, base_url: str) -> None:
        # Strip any trailing slash so URL formatting below stays uniform
        # regardless of how the subclass author writes the constant.
        self._base_url = base_url.rstrip('/')

    def get_unspent(self, address: TAddress, **kwargs) -> list:
        import requests
        url = '{base}/address/{addr}/utxo'.format(
            base=self._base_url, addr=address.decode('ascii'))
        utxos = requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP).json()
        if not utxos:
            # No UTXOs: skip the tip lookup, no script to reconstruct.
            return []
        tip = self._tip_height()
        script = self._lock_script(address)
        out = []
        for u in utxos:
            status = u.get('status') or {}
            if not status.get('confirmed'):
                # Mempool entries: 0 confirmations, same semantic as
                # blockchain.info's unconfirmed UTXOs.
                confirmations = 0
            else:
                block_height = status.get('block_height') or 0
                confirmations = max(0, tip - block_height + 1) if tip else 0
            out.append({
                'tx_hash': u['txid'],
                'tx_output_n': u['vout'],
                'value': u['value'],
                'script': script.hex(),
                'confirmations': confirmations,
            })
        return out

    def get_info(self, address: TAddress, **kwargs) -> dict:
        import requests
        url = '{base}/address/{addr}'.format(
            base=self._base_url, addr=address.decode('ascii'))
        stats = requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP).json()
        chain = stats.get('chain_stats') or {}
        mempool = stats.get('mempool_stats') or {}
        # Esplora reports per-side stats; the wallet reads the combined
        # `total_received` (chain + mempool), and we also surface the
        # derived `final_balance` / `n_tx` so any consumer looking at the
        # response shape sees what the blockchain.info backend returns.
        chain_received = chain.get('funded_txo_sum') or 0
        mempool_received = mempool.get('funded_txo_sum') or 0
        total_received = chain_received + mempool_received
        chain_spent = chain.get('spent_txo_sum') or 0
        mempool_spent = mempool.get('spent_txo_sum') or 0
        n_tx = (chain.get('tx_count') or 0) + (mempool.get('tx_count') or 0)
        return {
            'total_received': total_received,
            'final_balance': total_received - chain_spent - mempool_spent,
            'n_tx': n_tx,
        }

    def send_tx(self, rawtx: bytes, **kwargs) -> None:
        """Broadcast via POSTing the raw hex to `/tx`.

        Esplora's broadcast endpoint takes the raw tx hex as the request
        body and returns the new txid (or 4xx with an error message) on
        non-2xx. The wallet has already printed the tx id, so any
        non-2xx surfaces as a `RuntimeError`.
        """
        import requests
        url = '{base}/tx'.format(base=self._base_url)
        response = requests.post(url, data=rawtx.hex(),
                                 timeout=DEFAULT_TIMEOUT_HTTP)
        if not response.ok:
            raise RuntimeError(
                'broadcast failed: status={status} body={body}'.format(
                    status=response.status_code, body=response.text))

    def _tip_height(self) -> int:
        """Return the current chain tip height.

        The Esplora endpoint returns the height as plain text. The
        wallet only needs confirmations (a relative number), so any
        request error propagates and the caller surfaces it -- a tip
        that's off by one won't break the filter, only a missing tip
        response will.
        """
        import requests
        url = '{base}/blocks/tip/height'.format(base=self._base_url)
        return int(requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP).text.strip())

    @staticmethod
    def _lock_script(address: TAddress) -> bytes:
        """Reconstruct the lock script from a P2PKH/P2SH address.

        The Esplora UTXO endpoint omits the script; for the wallet's
        input builder to recognise the UTXO as spendable, the script
        has to be reconstructed. For P2PKH and P2SH addresses the
        address itself encodes the hash, so the script is uniquely
        determined.
        """
        from yubtc.crypto import make_lock_script
        return bytes(make_lock_script(address=address))


class BlockstreamBackend(EsploraBackend):
    """blockstream.info's public Esplora API."""

    DEFAULT_BASE_URL: str = 'https://blockstream.info/api'

    def __init__(self) -> None:
        super().__init__(self.DEFAULT_BASE_URL)


class MempoolSpaceBackend(EsploraBackend):
    """mempool.space's public Esplora API."""

    DEFAULT_BASE_URL: str = 'https://mempool.space/api'

    def __init__(self) -> None:
        super().__init__(self.DEFAULT_BASE_URL)


# Registry of provider name -> factory. Each entry is a no-arg callable
# that returns a fresh backend instance -- one line per provider keeps
# the list of supported providers easy to scan. The CLI and tests
# resolve names through `get_backend()`; never construct a backend
# directly from a string.
BACKENDS = {
    'blockchain.info': BlockchainInfoBackend,
    'blockstream': BlockstreamBackend,
    'mempool.space': MempoolSpaceBackend,
}


def get_backend(name: str = 'blockchain.info') -> NetworkBackend:
    """Return a fresh backend instance by registered name.

    Unknown names raise `ValueError` listing the registered names so
    the CLI can print a useful error. Each call returns a new instance
    so callers can swap freely without sharing state.
    """
    if name not in BACKENDS:
        raise ValueError(
            'unknown provider: {name!r} (known: {known})'.format(
                name=name, known=sorted(BACKENDS)))
    return BACKENDS[name]()


_current_backend = get_backend()


def get_current_backend() -> NetworkBackend:
    """Return the backend used by wallet/TPrivKey network calls.

    `set_current_backend(backend)` swaps this; `reset_backend()`
    restores the default `BlockchainInfoBackend`.
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
    _current_backend = get_backend()


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
