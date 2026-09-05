"""Network I/O used by the wallet.

The wallet talks to a `NetworkBackend`, not to a specific HTTP API.
Three providers are wired up:
- `BlockchainInfoBackend`: blockchain.info's public API (default).
- `BlockstreamBackend`: blockstream.info's public Esplora API.
- `MempoolSpaceBackend`: mempool.space's public Esplora API.

Plus the v0.3 resilience layer (mirrors the Rust port; spec.md
«Failover (v0.3)»):
- every HTTP request a backend issues is retried up to
  `DEFAULT_HTTP_RETRIES` times (the CLI `--retries` flag) with a
  capped exponential backoff, on transport faults and 5xx/408/429
  responses (a 429 honours a sane `Retry-After`); 4xx refusals and
  body-decode failures are final and never retried;
- `AutoBackend` (provider name `'auto'`) walks the three providers in
  registry order per request, first success wins and is remembered
  (sticky) for the rest of the command run; exhausting every backend
  raises `AllBackendsFailed` with a per-backend trail.

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
import time

from yubtc.fwd import (
    TAddress,
    DEFAULT_HTTP_RETRIES,
    DEFAULT_TIMEOUT_HTTP,
    HTTP_RETRY_AFTER_MAX,
    HTTP_RETRY_BASE_DELAY,
    HTTP_RETRY_MAX_DELAY,
)
from yubtc.util import NotNone, require_kwargs_only


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

    Concrete backends override the four methods below. The default
    kwargs catch-all lets callers (and tests) pass extra parameters
    without a signature churn -- the current wallet never uses them,
    but external backends can.
    """

    def name(self) -> str:
        """Registry name of this backend (mirrors the Rust trait's
        `name()`): what `--provider` accepts and what the auto-failover
        trail reports."""
        raise NotImplementedError

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


# ---------------------------------------------------------------------------
# Retry layer (v0.3 «Failover»). Mirrors the Rust
# `net::send_with_retries`: only the HTTP send is retried, the caller's
# own error mapping stays in charge of every terminal outcome, so with
# `retries=0` the behaviour is byte-for-byte the v0.1 one.
# ---------------------------------------------------------------------------


def _is_retryable_status(status_code: int) -> bool:
    """Status codes worth retrying: server faults (5xx), the
    request-timeout status (408) and rate limiting (429). Every other
    4xx is a deterministic refusal -- resending it would only duplicate
    the failure."""
    return status_code >= 500 or status_code in (408, 429)


def _backoff_delay(attempt: int) -> float:
    """Capped exponential backoff before retry `attempt` (0-based):
    `base * 2**attempt`, clamped to `HTTP_RETRY_MAX_DELAY`."""
    return min(HTTP_RETRY_BASE_DELAY * (2 ** attempt), HTTP_RETRY_MAX_DELAY)


def _retry_after_sane(response) -> float:
    """Parse the `Retry-After` header (integer-seconds form) and clamp
    it to the sane window. Returns the sleep in seconds, or `None` when
    the header is missing, non-numeric (e.g. HTTP-date form), negative
    or implausibly large -- meaning "use the regular backoff": a server
    must not be able to park the wallet for minutes with one header."""
    raw = response.headers.get('Retry-After')
    if raw is None:
        return None
    try:
        secs = int(raw.strip())
    except ValueError:
        return None
    if 0 <= secs <= HTTP_RETRY_AFTER_MAX:
        return float(secs)
    return None


def _request_with_retries(send, retries: int = DEFAULT_HTTP_RETRIES):
    """Run one HTTP request with the v0.3 retry policy.

    `send` is a no-arg callable performing a single request and
    returning the `requests` response object. Transport faults
    (`ConnectionError` -- which includes SSL errors -- and `Timeout`)
    and retryable statuses (5xx/408/429) are retried up to `retries`
    times, sleeping the capped exponential backoff between attempts
    (or the server's sane `Retry-After` on a 429). Everything terminal
    is returned as-is to the caller: with `retries=0` this helper is a
    plain passthrough, so the v0.1 error behaviour is untouched.
    """
    import requests
    attempt = 0
    while True:
        try:
            response = send()
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            if attempt >= retries:
                raise
            delay = _backoff_delay(attempt)
        else:
            if not _is_retryable_status(response.status_code):
                return response
            if attempt >= retries:
                return response
            delay = _backoff_delay(attempt)
            if response.status_code == 429:
                sane = _retry_after_sane(response)
                if sane is not None:
                    delay = sane
        time.sleep(delay)
        attempt += 1


class BlockchainInfoBackend(NetworkBackend):
    """Default backend: blockchain.info's public API.

    `base_url` overrides the default domain -- useful when the wallet
    runs behind a firewall that only allows a mirror. The endpoint
    paths (`/unspent`, `/balance`, `/pushtx`) are unchanged.

    `retries` is the v0.3 per-request retry count (the CLI `--retries`
    value); the default mirrors `fwd.DEFAULT_HTTP_RETRIES`.
    """

    DEFAULT_BASE_URL: str = 'https://blockchain.info'

    def __init__(self, base_url: str = DEFAULT_BASE_URL,
                 retries: int = DEFAULT_HTTP_RETRIES) -> None:
        self._base_url = base_url
        self._retries = retries

    def name(self) -> str:
        return 'blockchain.info'

    def get_unspent(self, address: TAddress, **kwargs) -> list:
        import requests
        from json.decoder import JSONDecodeError
        address = _address_str(address)
        url = '{base}/unspent?active={address}'.format(
            base=self._base_url, address=address)
        response = _request_with_retries(
            send=lambda: requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP),
            retries=self._retries)
        try:
            return response.json()['unspent_outputs']
        except JSONDecodeError:
            return []

    def get_info(self, address: TAddress, **kwargs) -> dict:
        import requests
        from json.decoder import JSONDecodeError
        address_str = _address_str(address)
        try:
            url = '{base}/balance?active={address}'.format(
                base=self._base_url, address=address_str)
            response = _request_with_retries(
                send=lambda: requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP),
                retries=self._retries)
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
        response = _request_with_retries(
            send=lambda: requests.post(url, data={'tx': rawtx.hex()},
                                       timeout=DEFAULT_TIMEOUT_HTTP),
            retries=self._retries)
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
        response = _request_with_retries(
            send=lambda: requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP),
            retries=self._retries)
        return response.text.strip()


class EsploraBackend(NetworkBackend):
    """Esplora-style backend shared by blockstream.info and mempool.space.

    Both serve the same JSON schema, so the parent implements the full
    surface and subclasses just pin the base URL. The wallet-shaped
    UTXO (`tx_hash`, `tx_output_n`, `value`, `script`, `confirmations`)
    is reconstructed from the Esplora response: the UTXO endpoint does
    not echo the script, so it's rebuilt from the queried address via
    `make_lock_script`. Confirmations come from the difference between
    the UTXO's `block_height` and the chain tip (`/blocks/tip/height`).

    `retries` is the v0.3 per-request retry count (the CLI `--retries`
    value); the default mirrors `fwd.DEFAULT_HTTP_RETRIES`.
    """

    def __init__(self, base_url: str,
                 retries: int = DEFAULT_HTTP_RETRIES) -> None:
        # Strip any trailing slash so URL formatting below stays uniform
        # regardless of how the subclass author writes the constant.
        self._base_url = base_url.rstrip('/')
        self._retries = retries

    def name(self) -> str:
        return 'esplora'

    def get_unspent(self, address: TAddress, **kwargs) -> list:
        import requests
        address = _address_str(address)
        url = '{base}/address/{addr}/utxo'.format(
            base=self._base_url, addr=address)
        utxos = _request_with_retries(
            send=lambda: requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP),
            retries=self._retries).json()
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
        stats = _request_with_retries(
            send=lambda: requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP),
            retries=self._retries).json()
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
        response = _request_with_retries(
            send=lambda: requests.post(url, data=rawtx.hex(),
                                       timeout=DEFAULT_TIMEOUT_HTTP),
            retries=self._retries)
        if not response.ok:
            raise RuntimeError(
                'broadcast failed: status={status} body={body}'.format(
                    status=response.status_code, body=response.text))

    def raw_transaction(self, txid: str, **kwargs) -> str:
        # Esplora serves raw transactions as plain hex at
        # `/tx/<txid>/hex`.
        import requests
        url = '{base}/tx/{txid}/hex'.format(base=self._base_url, txid=txid)
        response = _request_with_retries(
            send=lambda: requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP),
            retries=self._retries)
        return response.text.strip()

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
        response = _request_with_retries(
            send=lambda: requests.get(url, timeout=DEFAULT_TIMEOUT_HTTP),
            retries=self._retries)
        return int(response.text.strip())

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

    def __init__(self, retries: int = DEFAULT_HTTP_RETRIES) -> None:
        super().__init__(self.DEFAULT_BASE_URL, retries=retries)

    def name(self) -> str:
        return 'blockstream'


class MempoolSpaceBackend(EsploraBackend):
    """mempool.space's public Esplora API."""

    DEFAULT_BASE_URL: str = 'https://mempool.space/api'

    def __init__(self, retries: int = DEFAULT_HTTP_RETRIES) -> None:
        super().__init__(self.DEFAULT_BASE_URL, retries=retries)

    def name(self) -> str:
        return 'mempool.space'


# Registry of provider name -> factory. Each entry is a no-arg callable
# that returns a fresh backend instance -- one line per provider keeps
# the list of supported providers easy to scan. The CLI and tests
# resolve names through `get_backend()`; never construct a backend
# directly from a string.
#
# `'auto'` is deliberately NOT a registry entry: it is the v0.3
# failover pseudo-provider resolved specially by `get_backend` (and
# listed separately by the CLI's choice), built from the registry
# order below.
BACKENDS = {
    'blockchain.info': BlockchainInfoBackend,
    'blockstream': BlockstreamBackend,
    'mempool.space': MempoolSpaceBackend,
}

AUTO_ORDER = ('blockchain.info', 'blockstream', 'mempool.space')


class AllBackendsFailed(RuntimeError):
    """Every `--provider auto` backend failed (v0.3 failover).

    The message carries the per-backend trail -- `name: last error`
    entries joined by `; ` in attempt order -- so the user sees exactly
    what was tried and why each backend was rejected. Mirrors the Rust
    `NetError::AllBackendsFailed`.
    """


class AutoBackend(NetworkBackend):
    """`--provider auto` (v0.3, spec.md «Failover (v0.3)»): per-request
    failover across the registry order.

    Each method walks `backends` starting at the remembered preferred
    one (registry order until the first success), first success wins
    and is recorded. A preferred backend that starts failing is
    naturally demoted: the walk starts at it and continues down the
    remaining order, re-pinning on the next success. The preference is
    plain per-instance state -- a wallet is one command invocation, so
    this is "sticky within the run", never on disk and never across
    processes (stateless wallet).
    """

    @require_kwargs_only
    def __init__(self, backends: object = NotNone) -> None:
        self._backends = list(backends)
        self._preferred = None

    def name(self) -> str:
        return 'auto'

    def _order(self):
        """Attempt order: preferred first, then the rest of the list
        wrapping around -- every backend exactly once."""
        total = len(self._backends)
        start = self._preferred or 0
        return [(start + offset) % total for offset in range(total)]

    def _run(self, method_name: str, *args, **kwargs):
        """Call `method_name` on the first backend that answers;
        collect a `name: error` trail and raise `AllBackendsFailed`
        when every backend has been tried."""
        attempts = []
        for index in self._order():
            backend = self._backends[index]
            try:
                result = getattr(backend, method_name)(*args, **kwargs)
            except Exception as error:  # noqa: BLE001 -- any failure
                # (transport, refusal, decode) is a reason to move to
                # the next backend; the last error per backend is
                # reported verbatim in the trail.
                attempts.append('{name}: {error}'.format(
                    name=backend.name(), error=error))
            else:
                self._preferred = index
                return result
        raise AllBackendsFailed(
            'all backends failed: ' + '; '.join(attempts))

    def get_unspent(self, address: TAddress, **kwargs) -> list:
        return self._run('get_unspent', address, **kwargs)

    def get_info(self, address: TAddress, **kwargs) -> dict:
        return self._run('get_info', address, **kwargs)

    def send_tx(self, rawtx: bytes, **kwargs) -> None:
        return self._run('send_tx', rawtx, **kwargs)

    def raw_transaction(self, txid: str, **kwargs) -> str:
        return self._run('raw_transaction', txid, **kwargs)


def get_backends_for_auto(retries: int = DEFAULT_HTTP_RETRIES) -> list:
    """Registry order `--provider auto` walks: `blockchain.info` ->
    `blockstream` -> `mempool.space`, each a fresh instance with the
    given retry count. The `mock` harness entry is excluded -- it is
    not a real provider."""
    return [BACKENDS[name](retries=retries) for name in AUTO_ORDER]


def get_backend(name: str = 'blockchain.info',
                retries: int = DEFAULT_HTTP_RETRIES) -> NetworkBackend:
    """Return a fresh backend instance by registered name.

    Unknown names raise `ValueError` listing the registered names so
    the CLI can print a useful error. `'auto'` resolves to an
    `AutoBackend` over the registry order (v0.3 failover; each inner
    backend gets `retries`). Each call returns a new instance so
    callers can swap freely without sharing state.
    """
    if name == 'auto':
        return AutoBackend(backends=get_backends_for_auto(retries=retries))
    if name not in BACKENDS:
        raise ValueError(
            'unknown provider: {name!r} (known: {known})'.format(
                name=name, known=sorted(BACKENDS)))
    return BACKENDS[name](retries=retries)


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
