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
one takes the backend EXPLICITLY as its first argument and calls its
method (backend injection; there is no module-global current backend,
mirroring the Rust port's `net::get_address_info(backend, ...)`).
Callers resolve the backend once with `get_backend(name=...)` and
thread it through -- the registry is what powers the `--provider` CLI
flag.
"""
from yubtc.fwd import TAddress, DEFAULT_TIMEOUT_HTTP


def _address_str(address: TAddress) -> str:
    """Normalise an address to the `str` the URL builders need.

    v0.1 call sites pass base58 addresses as `bytes` (the
    `privkey2addr`/`pubkey2addr` return type); the Phase 13 multi-form
    wallet also queries native-SegWit/Taproot addresses, which are
    `str` (`bc1...`). Mirrors the Rust port, where an address is an
    opaque string end to end."""
    return address.decode('ascii') if isinstance(address, bytes) else address


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

    def raw_transaction(self, txid: str, **kwargs) -> str:
        """Fetch one raw transaction's wire-format hex by txid.

        Phase 15 (multisig Creator) and the Phase 14 PSBT Creator need
        the full previous transaction of a legacy input for the
        `NON_WITNESS_UTXO` field. The body IS the hex string (the
        Rust oracle's `decode_body_text` trims whitespace the same
        way the callers do)."""
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
        address = _address_str(address)
        url = '{base}/unspent?active={address}'.format(
            base=self._base_url, address=address)
        try:
            return requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP).json()['unspent_outputs']
        except JSONDecodeError:
            return []

    def get_info(self, address: TAddress, **kwargs) -> dict:
        import requests
        from json.decoder import JSONDecodeError
        address_str = _address_str(address)
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

    def raw_transaction(self, txid: str, **kwargs) -> str:
        # blockchain.info serves the wire-format hex behind
        # `/rawtx/<txid>?format=hex`; the body IS the hex string.
        import requests
        url = '{base}/rawtx/{txid}?format=hex'.format(
            base=self._base_url, txid=txid)
        return requests.get(url,
                            timeout=DEFAULT_TIMEOUT_HTTP).text.strip()


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
        address = _address_str(address)
        url = '{base}/address/{addr}/utxo'.format(
            base=self._base_url, addr=address)
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
            base=self._base_url, addr=_address_str(address))
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

    def raw_transaction(self, txid: str, **kwargs) -> str:
        # Esplora serves raw transactions as plain hex at
        # `/tx/<txid>/hex`.
        import requests
        url = '{base}/tx/{txid}/hex'.format(base=self._base_url, txid=txid)
        return requests.get(url,
                            timeout=DEFAULT_TIMEOUT_HTTP).text.strip()

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
        """Reconstruct the lock script from the address.

        The Esplora UTXO endpoint omits the script; for the wallet's
        input builder to recognise the UTXO as spendable, the script
        has to be reconstructed. For the forms the wallet owns
        (P2PKH/P2SH base58 and P2WPKH/P2TR `bc1...`) the address
        itself encodes the script, so it is uniquely determined.
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


# ---------------------------------------------------------------------------
# Module-level free functions: the public entry point.
#
# Backend injection: each function takes the backend as its first
# argument. The test suite can intercept by passing a stub backend
# (or monkeypatching the free function itself).
# ---------------------------------------------------------------------------


def get_address_unspent(backend: NetworkBackend, address: TAddress) -> list:
    """Return the UTXOs for `address` via `backend`."""
    return backend.get_unspent(address)


def get_address_info(backend: NetworkBackend, address: TAddress) -> dict:
    """Return the address's balance info via `backend`."""
    return backend.get_info(address)


def broadcastTx(backend: NetworkBackend, rawtx: bytes) -> None:
    """Broadcast a signed raw transaction via `backend`."""
    backend.send_tx(rawtx)
