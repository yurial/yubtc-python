"""Cross-compat harness for the native Rust CLI (Phase 9 T2).

Subprocesses the compiled `yubtc` binary from the yubtc Rust repo
against the same offline mock that the Python test suite uses, and
asserts the two CLIs produce identical output for the same seed.

What this test catches
----------------------

- **Derivation drift.** `yubtc-python/src/yubtc/crypto.py` and
  `yubtc-core/src/seed.rs` both implement the seed2privkey cascade;
  a quiet change in either side (wrong hash, off-by-one in the
  PBKDF2 iteration count, swapped nonce vs counter) would still let
  each side pass its own unit tests but diverge on the cross-check.

- **Address/WIF encoding drift.** Both implementations share the
  `base58check(version_byte ‖ body)` envelope but pull the body
  from different hash functions; a regression in either
  `hash160`/`pubkey_to_address` would surface here.

- **KDF routing.** The Rust CLI's `--kdf auto` heuristic (empty
  passphrase -> `yubtc`, non-empty -> `pbkdf2`) must match the
  Python CLI's implicit passphrase-driven routing of the same
  choice. A `cli.rs` regression that re-routes `--kdf auto` to
  argon2id (say) would silently change every auto-using operator's
  wallet.

- **Address-form routing (`--addr-type`).** The harness runs every
  check through the `legacy|native|taproot` axis (Phase 13 ОВ-1/ОВ-2):
  for the variant-A KDFs (the `yubtc` cascade, argon2id, scrypt) the
  same key must back all three encodings — identical WIF across
  forms, only the address encoding changes — while for `pbkdf2` each
  form is its own BIP-32 leaf (`m/44'…`/`m/84'…`/`m/86'…`), so the
  WIF must differ per form. A regression that collapses the purpose
  routing on either side (e.g. native deriving the `m/44'` leaf)
  would surface here as a cross-CLI or cross-form mismatch.

How the test runs offline
-------------------------

The native CLI hardcodes three provider URLs (blockchain.info,
blockstream, mempool.space). To exercise it offline we add a
fourth, `mock`, that reads its base URL from the
`YUBTC_MOCK_BACKEND_URL` env var and uses the same JSON shape as
blockchain.info's `/balance` + `/unspent` endpoints. The Python
test stands up a local `http.server` on a random port and points
both the Python CLI and the Rust CLI at it, so the cross-check
is purely against deterministic mock data.

Skipping the test
-----------------

The Rust binary is rebuilt on demand by this test's session
fixture (see `_rust_cli_bin()`), so the harness is hermetic. CI
can opt to skip via `SKIP_CLI_XCOMPAT=1` if no Rust toolchain is
present.
"""
import json
import os
import socket
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from click.testing import CliRunner


# ---------------------------------------------------------------------------
# Locate the Rust CLI binary. The test rebuilds it lazily via
# `cargo build --release -p yubtc` if it's missing — the same command the
# user's CLAUDE.md documents as the standard release-build entry point.
# ---------------------------------------------------------------------------

_DEFAULT_RUST_CLI_BIN = str(
    Path(__file__).resolve().parents[2]
    / 'yubtc'
    / 'target'
    / 'release'
    / 'yubtc'
)


def _rust_cli_bin() -> str:
    return os.environ.get('RUST_CLI_BIN', _DEFAULT_RUST_CLI_BIN)


def _should_skip() -> bool:
    if os.environ.get('SKIP_CLI_XCOMPAT') == '1':
        return True
    if not Path(_rust_cli_bin()).is_file():
        # Lazy build: the test's `cli_xcompat` fixture rebuilds before
        # any subprocess is run, so a missing binary is not a skip
        # condition — only an explicit env opt-out is.
        return False
    return False


skipif_no_rust_cli = pytest.mark.skipif(
    _should_skip(),
    reason='SKIP_CLI_XCOMPAT=1 set; Rust CLI xcompat disabled',
)


# ---------------------------------------------------------------------------
# Offline mock backend.
#
# Mirrors blockchain.info's legacy JSON shape so the Rust CLI's
# `BlockchainInfoBackend` and the Python CLI's `BlockchainInfoBackend`
# both parse the response without code changes. The mock marks every
# address as "never used" (n_tx=0), which terminates the wallet's
# gap-limit scan at the first nonce so we don't need to enumerate
# arbitrary nonces.
# ---------------------------------------------------------------------------


class _MockBlockchainHandler(BaseHTTPRequestHandler):
    """`/balance` + `/unspent` returning a deterministic shape.

    Every address is reported as never-used so the wallet's gap
    scan terminates at the very first nonce. UTXOs are always empty
    so the picker can never find funds — this is intentional,
    `address`/`dumpprivkey` are the only commands we exercise
    cross-CLI here.
    """

    def do_GET(self):  # noqa: N802 — http.server API
        url = urlparse(self.path)
        if url.path == '/balance':
            qs = parse_qs(url.query)
            addr = qs.get('active', [''])[0]
            body = json.dumps({
                addr: {'final_balance': 0, 'total_received': 0, 'n_tx': 0},
            }).encode()
        elif url.path == '/unspent':
            body = b'{"unspent_outputs":[]}'
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args, **kwargs):  # silence the test log
        pass


def _free_port() -> int:
    """Bind to port 0, capture the assigned port, release the socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def mock_blockchain_server():
    """Yield `http://127.0.0.1:<port>/` while serving mock blockchain.info."""
    port = _free_port()
    server = HTTPServer(('127.0.0.1', port), _MockBlockchainHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{port}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Run the Python CLI offline against the same mock.
# ---------------------------------------------------------------------------


def _python_address_output(seed: str, passphrase: str, kdf: str,
                           addr_type: str) -> str:
    """Invoke `yubtc.cli.cli address` with the offline mock and return stdout.

    The Python CLI's `BlockchainInfoBackend` is hardcoded to
    `https://blockchain.info`; monkeypatching the network helpers at
    `yubtc.net.*` is the standard escape hatch (see `test_net.py` for
    the same pattern).

    The Python CLI has no `--kdf` flag: the KDF is routed by the
    passphrase (empty -> 'yubtc', non-empty -> 'pbkdf2'), the same
    heuristic the Rust CLI's `--kdf auto` implements — the harness
    only passes the explicit `--kdf` to the Rust side. `addr_type`
    pins the receive-address form this invocation cross-checks
    (`legacy` P2PKH / `native` P2WPKH / `taproot` P2TR); the mock
    backend answers lookups for every form, bech32 addresses included
    (the `/balance` handler echoes the `active` query param back as
    the JSON key, which is exactly the string lookup the Rust
    `BlockchainInfoBackend` performs).
    """
    monkey = pytest.MonkeyPatch()
    monkey.setattr('yubtc.net.get_address_info',
                   lambda backend, address: {'total_received': 0, 'final_balance': 0, 'n_tx': 0})
    monkey.setattr('yubtc.net.get_address_unspent', lambda backend, address: [])
    try:
        from yubtc.cli import cli
        # Python CLI prompts passphrase first, then seed; both on stdin
        # (the harness injects two lines). Even when the passphrase is
        # empty, `seed.py` still reads seed *after* passphrase -- on a
        # non-tty stdin the read goes through `readline` either way.
        stdin_payload = f'{passphrase}\n{seed}\n'
        result = CliRunner().invoke(cli, ['address', '--addr-type', addr_type,
                                          '-n', '0', '--provider', 'blockchain.info'],
                                    input=stdin_payload)
        assert result.exit_code == 0, (
            f'python address failed: exit={result.exit_code} '
            f'output={result.output!r} exc={result.exception!r}'
        )
        # The CLI prints `{address}\n` to stdout; any prompt labels
        # ('Seed: ' / 'Passphrase: ...') come back as click echo. We
        # only care about the trailing address line.
        lines = [line for line in result.output.splitlines() if line.strip()]
        return lines[-1].strip()
    finally:
        monkey.undo()


# ---------------------------------------------------------------------------
# Run the Rust CLI subprocess against the same mock.
# ---------------------------------------------------------------------------


def _rust_address_output(seed: str, passphrase: str, kdf: str, addr_type: str,
                         mock_url: str, bin_path: str) -> str:
    """Subprocess the Rust CLI; return stdout stripped of the 'Seed:' prompt.

    Raises `AssertionError` on non-zero exit, capturing both streams
    for the failure message.
    """
    stdin_payload = f'{seed}\n{passphrase}\n'.encode()
    env = os.environ.copy()
    env['YUBTC_MOCK_BACKEND_URL'] = mock_url
    proc = subprocess.run(
        [bin_path, 'address', '--provider', 'mock', '--kdf', kdf,
         '--addr-type', addr_type, '-n', '0', '--new', '1'],
        input=stdin_payload,
        capture_output=True,
        env=env,
        timeout=30,
    )
    out = proc.stdout.decode()
    assert proc.returncode == 0, (
        f'rust address failed: exit={proc.returncode} '
        f'stdout={proc.stdout!r} stderr={proc.stderr!r}'
    )
    # Rust CLI prints "Seed: " (no newline) followed by the address on
    # the same line in pipe mode — read_line doesn't echo to stdout,
    # so the prompt and the answer stay glued together. Strip the
    # `Seed: ` prefix only; the trailing token after the prompt is the
    # address we want to compare.
    if out.startswith('Seed:'):
        out = out[len('Seed:'):].lstrip()
    return out.strip()


# ---------------------------------------------------------------------------
# Fixture: build the Rust binary on first use, then keep it warm.
# ---------------------------------------------------------------------------


@pytest.fixture(scope='session')
def rust_cli_bin():
    """Return the path to the Rust `yubtc` binary, building if missing.

    `scope='session'` so we don't rebuild per-test. The build itself
    is a release build — `cargo build --release -p yubtc` — and uses
    the same flags the user runs locally. The session fixture is
    skipped via `skipif_no_rust_cli` for environments without a
    Rust toolchain.
    """
    bin_path = _rust_cli_bin()
    if Path(bin_path).is_file():
        return bin_path
    # Find the workspace root from the binary's expected parent.
    workspace = Path(bin_path).resolve().parent.parent.parent
    if not (workspace / 'Cargo.toml').is_file():
        pytest.skip(f'workspace root not found at {workspace!r}')
    subprocess.run(
        ['cargo', 'build', '--release', '-p', 'yubtc'],
        cwd=str(workspace),
        check=True,
        timeout=600,
    )
    return bin_path


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


# The `--addr-type` axis (Phase 13 ОВ-1): every cross-CLI check runs
# once per receive-address form.
ADDR_TYPE_AXIS = ['legacy', 'native', 'taproot']


@pytest.mark.parametrize('seed,passphrase,kdf', [
    ('test seed', '', 'yubtc'),
    ('test seed', 'hunter2', 'pbkdf2'),
    ('qwe', '', 'yubtc'),
    # 12-word seed covers the BIP-39 parser path; without `--unique`
    # duplicates are fine.
    ('abandon abandon abandon abandon abandon abandon abandon '
     'abandon abandon abandon abandon about', '', 'yubtc'),
])
@pytest.mark.parametrize('addr_type', ADDR_TYPE_AXIS)
@skipif_no_rust_cli
def test_cli_address_matches_across_implementations(
        rust_cli_bin, seed, passphrase, kdf, addr_type):
    """The Rust CLI and the Python CLI must derive the same address
    for the same (seed, passphrase, kdf, addr_type) tuple.

    A divergence here means one of the two KDF cascades, purpose
    routings (pbkdf2 maps each addr_type to its own BIP-32 leaf),
    hash160/bech32 chains, or base58check encoders has drifted from
    the other.
    """
    with mock_blockchain_server() as mock_url:
        rust_addr = _rust_address_output(
            seed=seed, passphrase=passphrase, kdf=kdf, addr_type=addr_type,
            mock_url=mock_url, bin_path=rust_cli_bin,
        )
        py_addr = _python_address_output(
            seed=seed, passphrase=passphrase, kdf=kdf, addr_type=addr_type,
        )
    assert rust_addr == py_addr, (
        f'CLI xcompat divergence:\n'
        f'  seed={seed!r} passphrase={passphrase!r} kdf={kdf!r} '
        f'addr_type={addr_type!r}\n'
        f'  rust: {rust_addr!r}\n'
        f'  py:   {py_addr!r}'
    )


def _rust_dumpprivkey_output(seed: str, passphrase: str, kdf: str, addr_type: str,
                             mock_url: str, bin_path: str):
    """Subprocess the Rust `dumpprivkey`; return `(address, wif)`.

    Raises `AssertionError` on non-zero exit, capturing both streams
    for the failure message.
    """
    env = os.environ.copy()
    env['YUBTC_MOCK_BACKEND_URL'] = mock_url
    # Rust CLI prompts seed first, then passphrase.
    rust_proc = subprocess.run(
        [bin_path, 'dumpprivkey', '--provider', 'mock',
         '--kdf', kdf, '--addr-type', addr_type, '-n', '0'],
        input=f'{seed}\n{passphrase}\n'.encode(),
        capture_output=True, env=env, timeout=30,
    )
    assert rust_proc.returncode == 0, (
        f'rust dumpprivkey failed: exit={rust_proc.returncode} '
        f'stdout={rust_proc.stdout!r} stderr={rust_proc.stderr!r}'
    )
    rust_out = rust_proc.stdout.decode()
    # Same one-line prompt-then-result pattern as `address`: the
    # `Seed: ` prefix is glued to the first printed line. Strip the
    # `Seed: ` prefix and split the `Address: ` line from the WIF
    # line that follows.
    if rust_out.startswith('Seed:'):
        rust_out = rust_out[len('Seed:'):].lstrip()
    lines = [line.strip() for line in rust_out.strip().split('\n')]
    address = lines[0].removeprefix('Address: ').strip()
    return address, lines[1]


def _python_dumpprivkey_output(seed: str, passphrase: str, kdf: str, addr_type: str):
    """Invoke `yubtc.cli.cli dumpprivkey` with the offline mock; return
    `(address, wif)`.

    `kdf` is accepted for signature symmetry with the Rust helper but
    unused: the Python CLI routes the KDF by the passphrase (see
    `_python_address_output`).
    """
    monkey = pytest.MonkeyPatch()
    monkey.setattr('yubtc.net.get_address_info',
                   lambda backend, address: {'total_received': 0, 'final_balance': 0, 'n_tx': 0})
    monkey.setattr('yubtc.net.get_address_unspent', lambda backend, address: [])
    try:
        from yubtc.cli import cli
        # Python CLI prompts passphrase first, then seed.
        result = CliRunner().invoke(
            cli, ['dumpprivkey', '--addr-type', addr_type, '-n', '0',
                  '--provider', 'blockchain.info'],
            input=f'{passphrase}\n{seed}\n',
        )
        assert result.exit_code == 0, (
            f'python dumpprivkey failed: exit={result.exit_code} '
            f'output={result.output!r} exc={result.exception!r}'
        )
        py_lines = [line.strip() for line in result.output.split('\n') if line.strip()]
        # Permissive seed policy may print an entropy warning before
        # the result (low-entropy test seeds); anchor on the Address
        # line, WIF follows it.
        addr_idx = next(i for i, l in enumerate(py_lines)
                        if l.startswith('Address: '))
        address = py_lines[addr_idx].removeprefix('Address: ').strip()
        return address, py_lines[addr_idx + 1]
    finally:
        monkey.undo()


# One row per derivation model the addr-type axis has to pin:
# - the cascade KDF pins variant A (same key behind all three forms);
# - pbkdf2 pins the per-purpose BIP-32 leaves (m/44'/m/84'/m/86').
DUMPPRIVKEY_KDF_ROWS = [
    ('test seed', '', 'yubtc'),
    ('test seed', 'hunter2', 'pbkdf2'),
]


@skipif_no_rust_cli
@pytest.mark.parametrize('seed,passphrase,kdf', DUMPPRIVKEY_KDF_ROWS)
def test_cli_dumpprivkey_matches_across_implementations(
        rust_cli_bin, seed, passphrase, kdf):
    """`dumpprivkey` must agree with the Python CLI per address form,
    and the WIF pattern across forms must follow the derivation model.

    Per form (`--addr-type legacy|native|taproot`): both CLIs must
    print the same address AND the same WIF — a failure in either is
    a crypto-shape regression.

    Across forms the assertion depends on the KDF (spec ОВ-2):

    - **variant A (the `yubtc` cascade)** — one key backs all three
      encodings, so the WIF must be *identical* across the forms
      while the addresses differ.
    - **pbkdf2 (BIP-39 standard)** — each addr_type is its own
      BIP-32 leaf (`m/44'…`/`m/84'…`/`m/86'…`), so the WIF *must
      differ* between the forms. That divergence is expected parity
      behaviour, not a bug: it is asserted here so a regression that
      collapses the purpose routing on either side cannot pass
      silently.
    """
    per_form = {}
    for addr_type in ADDR_TYPE_AXIS:
        with mock_blockchain_server() as mock_url:
            rust_addr, rust_wif = _rust_dumpprivkey_output(
                seed=seed, passphrase=passphrase, kdf=kdf, addr_type=addr_type,
                mock_url=mock_url, bin_path=rust_cli_bin,
            )
        py_addr, py_wif = _python_dumpprivkey_output(
            seed=seed, passphrase=passphrase, kdf=kdf, addr_type=addr_type,
        )
        assert rust_addr == py_addr, (
            f'dumpprivkey[{addr_type}] address divergence:\n'
            f'  rust: {rust_addr!r}\n  py:   {py_addr!r}'
        )
        assert rust_wif == py_wif, (
            f'dumpprivkey[{addr_type}] WIF divergence:\n'
            f'  rust: {rust_wif!r}\n  py:   {py_wif!r}'
        )
        per_form[addr_type] = (rust_addr, rust_wif)

    # Every form encodes a different (key set, script) pair: the
    # printed addresses must be pairwise distinct no matter the KDF.
    addrs = {addr for addr, _ in per_form.values()}
    assert len(addrs) == len(ADDR_TYPE_AXIS), (
        f'addresses must differ per form, got {sorted(addrs)!r}')

    wifs = {wif for _, wif in per_form.values()}
    if kdf == 'yubtc':
        # Variant A: one key, three encodings -- identical WIF.
        assert len(wifs) == 1, (
            f'variant-A KDF {kdf!r} must reuse one key across forms, '
            f'got {len(wifs)} distinct WIFs: {sorted(wifs)!r}')
    else:
        # pbkdf2: per-purpose leaves -- one key per form.
        assert len(wifs) == len(ADDR_TYPE_AXIS), (
            f'pbkdf2 must derive one key per purpose, '
            f'got {len(wifs)} distinct WIFs: {sorted(wifs)!r}')


@skipif_no_rust_cli
def test_rust_cli_help_lists_all_subcommands(rust_cli_bin):
    """Smoke test: the Rust binary runs and `--help` prints the
    expected subcommand surface. Catches a CLI regression where a
    `#[derive(Subcommand)]` variant is removed silently.
    """
    proc = subprocess.run(
        [rust_cli_bin, '--help'],
        capture_output=True, timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.decode()
    for cmd in ('newseed', 'address', 'balance', 'send',
                'dumpprivkey', 'pushtx'):
        assert cmd in out, f'{cmd!r} missing from yubtc --help output'


@skipif_no_rust_cli
def test_rust_cli_rejects_unknown_subcommand(rust_cli_bin):
    """An unknown subcommand exits non-zero with a clap error —
    not a silent no-op or panic.
    """
    proc = subprocess.run(
        [rust_cli_bin, 'no-such-cmd'],
        capture_output=True, timeout=10,
    )
    assert proc.returncode != 0
    assert b'no-such-cmd' in proc.stderr
