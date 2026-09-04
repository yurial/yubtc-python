"""Multi-sig cross-compat harness: the Rust CLI (`yubtc ms ...`) versus
the Python mirror (`yubtc.script` / `yubtc.wallet`), Phase 15 stage 3.

Per spec.md «Python-зеркало (yubtc-python)» -- xcompat: the Rust CLI
subprocess runs `ms create` / `ms send` (+ the Phase 14
`psbt sign|combine|finalize|extract` chain) against the Python
functions on the same (N, M, keys, nonce) tuples; identical
hex/base64 at every stage is the parity gate. `ms send` is the only
network-touching step -- it runs behind the `YUBTC_MOCK_BACKEND_URL`
mock gate (`--provider mock`): the same local HTTP server feeds both
the CLI and the Python `BlockchainInfoBackend` adapter, so both sides
see byte-identical UTXO/raw-transaction data.

Skipping
--------

The `ms` CLI group landed with Rust Phase 15 stage 2 (issue-multisig
`2f3e8cb`); the probe below stays only as a guard for checkouts whose
binary predates it (or `SKIP_CLI_XCOMPAT=1`): then the tests still
self-skip cleanly. The parity KAT in `test_multisig.py` covers the
Python side independently of this harness.

Interface assumptions (spec CLI section, `yubtc ms ...`)
--------------------------------------------------------

- `ms create N M [--key HEX|WIF ...] [-n NONCE]` -- stdout is the
  pinned three-line block `m-of-n: M-of-N` / `address:` / `redeem:`;
  the seed prompt goes to stderr and the stdin carries the seed line
  then the passphrase line (the shared prompt convention). Watch-only
  invocations read no stdin.
- `ms send ADDR AMOUNT N M ... -n NONCE --provider mock` -- stdout is
  exactly one line, the base64 PSBT (the fee line goes to stderr).
- If the landed stage-2 surface deviates (prompt order, flags), the
  helpers below are the place to adapt.
"""
import json
import os
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest

from yubtc.crypto import privkey2privwif, privkey2pubkey, seed2privkey
from yubtc.hash import hash160
from yubtc.net import BlockchainInfoBackend
from yubtc.psbt import (PsbtTransaction, PsbtTxIn, PsbtTxOut,
                        extract_transaction, finalize_psbt, from_base64,
                        psbt_summary, sign_psbt_input, to_base64)
from yubtc.script import extract_multisig_quorum, make_p2sh_lock_script
from yubtc.wallet import ms_create_address, ms_create_psbt

# ---------------------------------------------------------------------------
# Locate (and lazily build) the Rust CLI binary -- the sibling Rust
# worktree first (it carries the Phase 15 `ms` group), then the old
# side-by-side convention of test_cli_xcompat.py.
# ---------------------------------------------------------------------------


def _default_rust_cli_bin_candidates() -> list:
    """Binary locations, best first.

    1. The sibling Rust worktree carrying the Phase 15 `ms` group
       (`wt/<rust-repo>/issue-multisig` next to this checkout).
    2. The side-by-side main checkouts (the old convention).
    """
    here = Path(__file__).resolve()
    return [
        here.parents[3] / 'yubtc' / 'issue-multisig' / 'target' / 'release'
        / 'yubtc',
        here.parents[2] / 'yubtc' / 'target' / 'release' / 'yubtc',
    ]


def _rust_cli_bin() -> str:
    env = os.environ.get('RUST_CLI_BIN')
    if env:
        return env
    for cand in _default_rust_cli_bin_candidates():
        if cand.is_file():
            return str(cand)
    return str(_default_rust_cli_bin_candidates()[0])


@pytest.fixture(scope='session')
def rust_cli_bin():
    """The Rust binary path, built on first use (session scope)."""
    if os.environ.get('SKIP_CLI_XCOMPAT') == '1':
        pytest.skip('SKIP_CLI_XCOMPAT=1 set; Rust CLI xcompat disabled')
    bin_path = _rust_cli_bin()
    if Path(bin_path).is_file():
        return bin_path
    workspace = Path(bin_path).resolve().parent.parent.parent
    if not (workspace / 'Cargo.toml').is_file():
        pytest.skip(f'workspace root not found at {workspace!r}')
    subprocess.run(
        ['cargo', 'build', '--release', '-p', 'yubtc'],
        cwd=str(workspace), check=True, timeout=900,
    )
    return bin_path


@pytest.fixture(scope='session')
def ms_cli(rust_cli_bin):
    """The binary path, but only when the `ms` group exists (the
    Phase 15 stage-2 probe; absent -> every test in this module
    skips)."""
    probe = subprocess.run([rust_cli_bin, 'ms', '--help'],
                           input=b'', capture_output=True, timeout=30)
    if probe.returncode != 0:
        pytest.skip('the Rust CLI has no `ms` group yet (Phase 15 '
                    'stage 2 not landed); test_multisig.py pins the '
                    'Python side until it does')
    return rust_cli_bin


# ---------------------------------------------------------------------------
# CLI helpers.
# ---------------------------------------------------------------------------

XC_SEED = 'phase15msxcompat'
XC_SEED_B = 'phase15msxcompat-b'


def _run_ms(bin_path: str, args: list, stdin: str = '',
            mock_url: str = None):
    """Run one `ms` subcommand; return (rc, stdout, stderr)."""
    env = os.environ.copy()
    if mock_url is not None:
        env['YUBTC_MOCK_BACKEND_URL'] = mock_url
    proc = subprocess.run([bin_path, 'ms'] + args,
                          input=stdin.encode(), capture_output=True,
                          env=env, timeout=60)
    return proc.returncode, proc.stdout.decode(), proc.stderr.decode()


def _seed_stdin(seed: str = XC_SEED, passphrase: str = '') -> str:
    """The assumed stdin convention: seed line, passphrase line."""
    return f'{seed}\n{passphrase}\n'


def _parse_create_output(out: str) -> dict:
    """Parse the pinned `ms create` stdout block."""
    lines = out.strip().splitlines()
    assert len(lines) == 3, out
    assert lines[0].startswith('m-of-n: ')
    assert lines[1].startswith('address: ')
    assert lines[2].startswith('redeem: ')
    m_of_n = lines[0][len('m-of-n: '):]
    return {'m_of_n': m_of_n,
            'address': lines[1][len('address: '):],
            'redeem_hex': lines[2][len('redeem: '):]}


# ---------------------------------------------------------------------------
# The fixture tuples: one seed for the Creator wallet (own key at
# nonce 0), a second seed for the cosigner wallet -- real quorum
# participants hold different seeds. The cosigner keys enter the
# quorum as pubkeys; `psbt sign` under XC_SEED_B finds the cosigner
# key by membership (a nonce-0 walk under XC_SEED would hit the
# Creator's already-present signature idempotently and stop, so a
# one-seed quorum cannot complete through the walk).
# ---------------------------------------------------------------------------


def _xc_key(nonce: int, seed: str = XC_SEED):
    return seed2privkey(seed=seed, nonce=nonce, passphrase='',
                        kdf='yubtc')


def _xc_pub(nonce: int, seed: str = XC_SEED) -> bytes:
    return privkey2pubkey(_xc_key(nonce, seed))


def _xc_quorum_pubkeys() -> list:
    """The full quorum key set for (n=3, m=2): the Creator's own key
    at nonce 0 + the two cosigner pubkeys (wallet B, nonces 0 and 1)."""
    return [_xc_pub(0), _xc_pub(0, XC_SEED_B), _xc_pub(1, XC_SEED_B)]


# ---------------------------------------------------------------------------
# Offline parity: `ms create` (R-MS-1..R-MS-4 at the CLI boundary).
# ---------------------------------------------------------------------------


def test_ms_cli_create_matches_python(ms_cli):
    """`ms create 3 2 --key k1 --key k2 -n 0` must print exactly the
    address + redeem the Python `ms_create_address` derives from the
    same key set."""
    args = ['create', '3', '2',
            '--key', _xc_pub(1).hex(), '--key', _xc_pub(2).hex(),
            '-n', '0']
    rc, out, err = _run_ms(ms_cli, args, stdin=_seed_stdin())
    assert rc == 0, f'ms create failed: rc={rc} err={err!r}'
    cli = _parse_create_output(out)
    addr, redeem = ms_create_address(
        n=3, m=2, keys=[_xc_pub(1), _xc_pub(2), _xc_pub(0)])
    assert cli['m_of_n'] == '2-of-3'
    assert cli['address'] == addr
    assert cli['redeem_hex'] == redeem.hex()


def test_ms_cli_create_is_invariant_under_argument_order(ms_cli):
    """R-MS-4 through the CLI surface: shuffled --key order (and the
    N/M positionals kept) must give the same address."""
    args = ['create', '3', '2',
            '--key', _xc_pub(2).hex(), '--key', _xc_pub(1).hex(),
            '-n', '0']
    rc, out, err = _run_ms(ms_cli, args, stdin=_seed_stdin())
    assert rc == 0, f'ms create failed: rc={rc} err={err!r}'
    cli = _parse_create_output(out)
    addr, redeem = ms_create_address(
        n=3, m=2, keys=[_xc_pub(1), _xc_pub(2), _xc_pub(0)])
    assert cli['address'] == addr
    assert cli['redeem_hex'] == redeem.hex()
    assert list(extract_multisig_quorum(script=redeem)[1]) \
        == sorted([_xc_pub(0), _xc_pub(1), _xc_pub(2)])


def test_ms_cli_create_watch_only_needs_no_stdin(ms_cli):
    """Watch-only create: two synthetic cosigner keys, no `-n`, no
    seed -- offline pure function."""
    args = ['create', '2', '2', '--key', _xc_pub(1).hex(),
            '--key', _xc_pub(2).hex()]
    rc, out, err = _run_ms(ms_cli, args)
    assert rc == 0, f'ms create failed: rc={rc} err={err!r}'
    cli = _parse_create_output(out)
    addr, redeem = ms_create_address(n=2, m=2,
                                     keys=[_xc_pub(1), _xc_pub(2)])
    assert cli['address'] == addr
    assert cli['redeem_hex'] == redeem.hex()


def test_ms_cli_create_own_wif_sugar_and_foreign_refusal(ms_cli):
    """`--key <WIF>` sugar: the own WIF verifies against the derived
    key at `-n` (same address); a foreign WIF fails with the
    ForeignWif wallet error (R-MS-6)."""
    own_wif = privkey2privwif(privkey=_xc_key(0))
    args = ['create', '3', '2',
            '--key', _xc_pub(1).hex(), '--key', _xc_pub(2).hex(),
            '--key', own_wif, '-n', '0']
    rc, out, err = _run_ms(ms_cli, args, stdin=_seed_stdin())
    assert rc == 0, f'ms create failed: rc={rc} err={err!r}'
    cli = _parse_create_output(out)
    addr, _redeem = ms_create_address(
        n=3, m=2, keys=[_xc_pub(1), _xc_pub(2), _xc_pub(0)])
    assert cli['address'] == addr

    foreign_wif = privkey2privwif(privkey=_xc_key(9))
    args = ['create', '3', '2',
            '--key', _xc_pub(1).hex(), '--key', _xc_pub(2).hex(),
            '--key', foreign_wif, '-n', '0']
    rc, out, err = _run_ms(ms_cli, args, stdin=_seed_stdin())
    assert rc != 0
    assert 'WIF does not match' in err


# ---------------------------------------------------------------------------
# Creator parity behind the YUBTC_MOCK_BACKEND_URL gate (`ms send`).
# ---------------------------------------------------------------------------

# The mock fixture: one 60_000-sat UTXO at the quorum address, vout 0
# of a deterministic prev tx (internal txid 0x77*32).
_MOCK_VALUE = 60_000


def _mock_prev_tx(redeem: bytes):
    """Prev tx paying 60_000 sat to the fixture quorum's P2SH
    script; returned as (PsbtTransaction, wire hex, txid hex)."""
    spk = bytes(make_p2sh_lock_script(hash160=hash160(redeem)))
    prev = PsbtTransaction(
        version=2,
        vin=(PsbtTxIn(txhash=b'\x77' * 32, n=0, script=b'',
                      sequence=0xffffffff, witness=()),),
        vout=(PsbtTxOut(amount=_MOCK_VALUE, script=spk),), locktime=0)
    return prev, prev.serialize_wire().hex(), prev.id().hex()


class _MockMsHandler(BaseHTTPRequestHandler):
    """`/unspent` + `/rawtx` serving the fixture quorum UTXO (the
    blockchain.info shapes both the Rust mock backend and the Python
    `BlockchainInfoBackend` consume)."""

    unspent_address = ''
    utxo_txid = ''
    utxo_script_hex = ''
    raw_hex = ''

    def do_GET(self):  # noqa: N802 -- http.server API
        url = urlparse(self.path)
        if url.path == '/unspent':
            body = json.dumps({'unspent_outputs': [{
                'tx_hash': type(self).utxo_txid,
                'tx_output_n': 0,
                'value': _MOCK_VALUE,
                'script': type(self).utxo_script_hex,
                'confirmations': 6,
            }]}).encode()
        elif url.path.startswith('/rawtx/'):
            body = type(self).raw_hex.encode()
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


@contextmanager
def mock_ms_server(redeem: bytes):
    """Serve the fixture UTXO while yielding the base URL. The handler
    state is class-level: `HTTPServer` spawns a fresh handler per
    request, so the class attributes carry the fixture."""
    addr, _redeem = ms_create_address(n=3, m=2, keys=_xc_quorum_pubkeys())
    prev, raw_hex, txid_hex = _mock_prev_tx(redeem)
    _MockMsHandler.unspent_address = addr
    _MockMsHandler.utxo_txid = txid_hex
    _MockMsHandler.utxo_script_hex = bytes(
        make_p2sh_lock_script(hash160=hash160(redeem))).hex()
    _MockMsHandler.raw_hex = raw_hex
    server = HTTPServer(('127.0.0.1', 0), _MockMsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_address[1]}'
    finally:
        server.shutdown()
        server.server_close()


def _dst_address() -> str:
    """A valid bech32 destination (fixture key's native address)."""
    from yubtc.crypto import pubkey2segwit_addr
    return pubkey2segwit_addr(pubkey=_xc_pub(9))


def _ms_send_args(dst: str) -> list:
    return ['send', dst, '0.0005', '3', '2',
            '--key', _xc_pub(0, XC_SEED_B).hex(),
            '--key', _xc_pub(1, XC_SEED_B).hex(),
            '-n', '0', '-c', '6', '-f', '0', '-k', '1000',
            '--provider', 'mock']


def test_ms_cli_send_matches_python_creator(ms_cli):
    """`ms send` (mock) must emit byte-for-byte the PSBT the Python
    `ms_create_psbt` builds over the same mock data: same fee loop,
    same REDEEM_SCRIPT fields, same own partial signatures."""
    _addr, redeem = ms_create_address(n=3, m=2, keys=_xc_quorum_pubkeys())
    dst = _dst_address()
    with mock_ms_server(redeem) as mock_url:
        rc, out, err = _run_ms(ms_cli, _ms_send_args(dst),
                               stdin=_seed_stdin(), mock_url=mock_url)
        assert rc == 0, f'ms send failed: rc={rc} err={err!r}'
        cli_b64 = out.strip().splitlines()[-1]
        backend = BlockchainInfoBackend(base_url=mock_url)
        outcome = ms_create_psbt(seed=XC_SEED, passphrase='',
                                 backend=backend, dst=dst, amount=50_000,
                                 n=3, m=2,
                                 keys=[_xc_pub(0, XC_SEED_B),
                                       _xc_pub(1, XC_SEED_B)],
                                 own_nonce=0, confirmations=6, feekb=1000,
                                 fee=0)
    assert cli_b64 == outcome.psbt_b64
    # And it decodes to the quorum input with the own signature
    # (psbt decode parity, the Python side of the `psbt decode` dump).
    psbt = from_base64(s=cli_b64)
    assert psbt.inputs[0].redeem_script == redeem
    assert [k for k, _sig in psbt.inputs[0].partial_sigs] == [_xc_pub(0)]
    rc, dump, err = _run_psbt(ms_cli, ['decode'], cli_b64 + '\n')
    assert rc == 0, f'psbt decode failed: rc={rc} err={err!r}'
    summary = psbt_summary(psbt=from_base64(s=cli_b64))
    assert summary.txid_hex in dump
    assert str(summary.fee_sat) in dump


def test_ms_cli_chain_sign_combine_finalize_extract_matches_python(ms_cli):
    """The full pipeline: CLI `ms send` -> CLI `psbt sign` (cosigner,
    membership signing) -> `combine` -> `finalize` -> `extract`; the
    Python mirror replays the same stages on the same PSBT and every
    stage must agree byte-for-byte."""
    _addr, redeem = ms_create_address(n=3, m=2, keys=_xc_quorum_pubkeys())
    dst = _dst_address()
    with mock_ms_server(redeem) as mock_url:
        rc, out, err = _run_ms(ms_cli, _ms_send_args(dst),
                               stdin=_seed_stdin(), mock_url=mock_url)
        assert rc == 0, f'ms send failed: rc={rc} err={err!r}'
        cli_b64 = out.strip().splitlines()[-1]

    # CLI cosigner signature (the cosigner IS this fixture wallet at
    # nonce 1 -- `psbt sign` finds it by membership).
    rc, signed, err = _run_psbt(ms_cli, ['sign'],
                                _seed_stdin(seed=XC_SEED_B) + cli_b64
                                + '\n')
    assert rc == 0, f'psbt sign failed: rc={rc} err={err!r}'
    signed = signed.strip().splitlines()[-1]
    # CLI finalize + extract.
    rc, finalized, err = _run_psbt(ms_cli, ['finalize'], signed + '\n')
    assert rc == 0, f'psbt finalize failed: rc={rc} err={err!r}'
    finalized = finalized.strip()
    rc, hexed, err = _run_psbt(ms_cli, ['extract'], finalized + '\n')
    assert rc == 0, f'psbt extract failed: rc={rc} err={err!r}'
    hexed = hexed.strip()

    # Python, the same stages: the cosigner wallet (seed B) adds its
    # signature to the Creator's PSBT by membership, then the
    # Finalizer/Extractor run on the merged PSBT.
    py = from_base64(s=cli_b64)
    assert sign_psbt_input(psbt=py, index=0,
                           privkey=_xc_key(0, XC_SEED_B)) is True
    assert to_base64(psbt=py) == signed
    finalize_psbt(psbt=py)
    assert to_base64(psbt=py) == finalized
    wire = extract_transaction(psbt=py).serialize_wire().hex()
    assert wire == hexed


def _run_psbt(bin_path: str, args: list, stdin: str):
    proc = subprocess.run([bin_path, 'psbt'] + args,
                          input=stdin.encode(), capture_output=True,
                          timeout=60)
    return proc.returncode, proc.stdout.decode(), proc.stderr.decode()
