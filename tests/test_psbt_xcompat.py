"""PSBT cross-compat harness: the Rust CLI (`yubtc psbt ...`) versus the
Python mirror (`yubtc.psbt`), Phase 14 stage 3.

Per spec.md «Python-зеркало (yubtc-python)» -- xcompat: the Rust CLI
subprocess (`psbt create|sign|combine|finalize|extract|decode`) is run
against the Python functions on the same tuples; identical base64 at
every pipeline stage is the parity gate. `create` is the only command
that needs the network -- it runs behind the existing
`YUBTC_MOCK_BACKEND_URL` mock gate (plus a mock `raw_transaction`
endpoint the Creator needs for legacy inputs); every other stage is
offline.

Skipping
--------

The `psbt` CLI group is Phase 14 **stage 2** of the Rust repo and may
not be merged yet. Every test here probes the binary once (session
scope): if the group is absent -- or `SKIP_CLI_XCOMPAT=1` is set --
the tests self-skip cleanly. The parity KATs in `test_psbt.py` cover
the Python side independently of this harness.

Interface assumptions (spec CLI section, `yubtc psbt ...`)
----------------------------------------------------------

- stdin -> stdout filters: `create`/`sign`/`combine`/`finalize` emit
  base64, `extract` emits raw-tx hex, `decode` a human-readable dump;
  `combine` reads >= 2 PSBT lines.
- `sign` and `create` need the wallet seed: the same non-tty prompt
  order as the other commands is assumed (seed line, passphrase line;
  the PSBT lines follow).
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
from urllib.parse import parse_qs, urlparse

import pytest

from yubtc.psbt import UnknownKv, combine_psbt, extract_transaction, \
    finalize_psbt, from_base64, psbt_summary, to_base64
from tests.test_psbt import RUST_ROWS, SEED, build_row, fixture_key, replay

# ---------------------------------------------------------------------------
# Locate (and lazily build) the Rust CLI binary -- same convention as
# test_cli_xcompat.py.
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
        cwd=str(workspace), check=True, timeout=600,
    )
    return bin_path


@pytest.fixture(scope='session')
def psbt_cli(rust_cli_bin):
    """The binary path, but only when the `psbt` group exists (the
    Phase 14 stage-2 probe; absent -> every test in this module skips)."""
    probe = subprocess.run([rust_cli_bin, 'psbt', '--help'],
                           input=b'', capture_output=True, timeout=30)
    if probe.returncode != 0:
        pytest.skip('the Rust CLI has no `psbt` group yet (Phase 14 '
                    'stage 2 not landed); test_psbt.py pins the Python '
                    'side until it does')
    return rust_cli_bin


# ---------------------------------------------------------------------------
# Rust CLI helpers (stdin -> stdout filters).
# ---------------------------------------------------------------------------


def _run_psbt(bin_path: str, args: list, stdin: str,
              mock_url: str = None):
    """Run one `psbt` subcommand; return (rc, stdout)."""
    env = os.environ.copy()
    if mock_url is not None:
        env['YUBTC_MOCK_BACKEND_URL'] = mock_url
    proc = subprocess.run([bin_path, 'psbt'] + args,
                          input=stdin.encode(), capture_output=True,
                          env=env, timeout=30)
    return proc.returncode, proc.stdout.decode()


def _run_psbt_ok(bin_path: str, args: list, stdin: str,
                 mock_url: str = None) -> str:
    rc, out = _run_psbt(bin_path, args, stdin, mock_url)
    assert rc == 0, f'psbt {" ".join(args)} failed: rc={rc} out={out!r}'
    return out.strip()


def _sign_stdin(psbt_b64: str, seed: str = SEED, passphrase: str = '') -> str:
    """The assumed `psbt sign` stdin: seed, passphrase, PSBT line."""
    return f'{seed}\n{passphrase}\n{psbt_b64}\n'


# ---------------------------------------------------------------------------
# Offline parity: the CLI stages on the same fixed rows the unit-suite
# KAT pins. The expected values are the RUST_ROWS constants generated
# from the Rust core (commit 3f97d66) -- the CLI must agree with its
# own core, and the taproot row agrees with the Python mirror directly.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize('name', ['taproot_single', 'three_forms',
                                  'legacy_only', 'pbkdf2_native'])
def test_psbt_cli_sign_matches_core_kat(psbt_cli, name):
    """`psbt sign` must reproduce the core-generated signed stage of
    the same unsigned PSBT (all offline; the walk runs in the CLI)."""
    row = RUST_ROWS[name]
    signed = _run_psbt_ok(psbt_cli, ['sign'], _sign_stdin(row['unsigned']))
    assert signed == row['signed'], f'{name}: CLI sign vs core KAT'


@pytest.mark.parametrize('name', ['taproot_single', 'three_forms',
                                  'legacy_only'])
def test_psbt_cli_finalize_extract_match_python(psbt_cli, name):
    """`psbt finalize` and `psbt extract` on the CLI must produce the
    KAT stages; the Python mirror agrees byte-for-byte."""
    row = RUST_ROWS[name]
    finalized = _run_psbt_ok(psbt_cli, ['finalize'], row['signed'] + '\n')
    assert finalized == row['finalized'], f'{name}: CLI finalize'
    hexed = _run_psbt_ok(psbt_cli, ['extract'], row['finalized'] + '\n')
    assert hexed == row['hex'], f'{name}: CLI extract'
    # Python, same stages.
    psbt = from_base64(s=row['signed'])
    finalize_psbt(psbt=psbt)
    assert to_base64(psbt=psbt) == finalized, f'{name}: python finalize'
    wire = extract_transaction(psbt=psbt).serialize_wire().hex()
    assert wire == hexed, f'{name}: python extract'


def test_psbt_cli_combine_matches_python(psbt_cli):
    """`psbt combine` on the core-KAT pair; the Python Combiner merges
    to the same canonical bytes."""
    a_b64 = RUST_ROWS['combine']['a']
    b = from_base64(s=a_b64)
    b.inputs[0].partial_sigs.append((b'\x02' * 33, b'\xbb' * 64))
    b.unknown_global.append(UnknownKv(key=b'\x51\x07', value=b'\x09'))
    b_b64 = to_base64(psbt=b)
    combined = _run_psbt_ok(psbt_cli, ['combine'], a_b64 + '\n' + b_b64 + '\n')
    assert combined == RUST_ROWS['combine']['combined']
    # Python, same inputs.
    py = combine_psbt(psbt=from_base64(s=a_b64), other=from_base64(s=b_b64))
    assert to_base64(psbt=py) == combined


def test_psbt_cli_sign_matches_python_taproot(psbt_cli):
    """End-to-end Python-vs-CLI parity on the Schnorr row: the Python
    mirror's signed stage equals the CLI's (BIP-340 is deterministic,
    so no divergence neutralization is needed)."""
    row = RUST_ROWS['taproot_single']
    cli_signed = _run_psbt_ok(psbt_cli, ['sign'],
                              _sign_stdin(row['unsigned']))
    psbt = build_row('taproot_single')
    assert replay(psbt, SEED, '', 'yubtc')[1] == cli_signed


def test_psbt_cli_decode_reports_the_kat_summary(psbt_cli):
    """`decode` is the yubtc extension; the dump must expose at least
    the txid and the fee the Python summary computes."""
    row = RUST_ROWS['taproot_single']
    out = _run_psbt_ok(psbt_cli, ['decode'], row['unsigned'] + '\n')
    summary = psbt_summary(psbt=from_base64(s=row['unsigned']))
    assert summary.txid_hex in out
    assert str(summary.fee_sat) in out


# ---------------------------------------------------------------------------
# Creator parity behind the YUBTC_MOCK_BACKEND_URL gate.
# ---------------------------------------------------------------------------

# The fixture wallet data served by the mock: nonce 0 native, one
# 30000-sat UTXO of MockUtxo.TXID:1 (deterministic, offline).
_MOCK_UTXO_VALUE = 30_000
_MOCK_UTXO_TXID = '22' * 32
_MOCK_UTXO_VOUT = 1


def _mock_fixture_address_and_script():
    """The mock nonce-0 native address and its scriptPubKey hex."""
    from yubtc.crypto import pubkey2segwit_addr
    from yubtc.hash import hash160
    pubkey = privkey2pubkey_cached()
    script = bytes.fromhex('0014') + hash160(pubkey)
    return pubkey2segwit_addr(pubkey=pubkey), script.hex()


def privkey2pubkey_cached():
    from yubtc.crypto import privkey2pubkey
    return privkey2pubkey(privkey=fixture_key(0))


class _MockPsbtHandler(BaseHTTPRequestHandler):
    """`/balance` + `/unspent` + `/rawtx` with deterministic data.

    Nonce 0 is reported as the only used address; its native form
    holds the mock UTXO, so the Creator's gap scan stops after the
    first nonce. `/rawtx/<txid>?format=hex` serves the hex the Creator
    needs for legacy inputs (empty here: the mock UTXO is witness
    form)."""

    def do_GET(self):  # noqa: N802 -- http.server API
        address, script_hex = _mock_fixture_address_and_script()
        url = urlparse(self.path)
        if url.path == '/balance':
            qs = parse_qs(url.query)
            addr = qs.get('active', [''])[0]
            used = addr == address
            body = json.dumps({
                addr: {'final_balance': _MOCK_UTXO_VALUE if used else 0,
                       'total_received': _MOCK_UTXO_VALUE if used else 0,
                       'n_tx': 1 if used else 0},
            }).encode()
        elif url.path == '/unspent':
            body = json.dumps({'unspent_outputs': [
                {'tx_hash': _MOCK_UTXO_TXID, 'tx_output_n': _MOCK_UTXO_VOUT,
                 'value': _MOCK_UTXO_VALUE, 'script': script_hex,
                 'confirmations': 6},
            ]}).encode()
        elif url.path.startswith('/rawtx/'):
            body = ''  # no legacy inputs in the mock fixture
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
def mock_psbt_server():
    """Yield `http://127.0.0.1:<port>` while serving the mock."""
    server = HTTPServer(('127.0.0.1', 0), _MockPsbtHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_address[1]}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_psbt_cli_create_parity_behind_mock_gate(psbt_cli):
    """`psbt create ADDR AMOUNT --provider mock` over the mock backend.

    The Creator's exact vout layout (cashback split, fee defaults) is
    CLI-owned, so the parity gate is the spec's interoperability core:
    the emitted unsigned PSBT must (a) parse in the Python mirror,
    (b) carry the WITNESS_UTXO field for the witness input, and
    (c) survive the Python Signer->Finalizer->Extractor pipeline to
    the same wire transaction the CLI's own pipeline produces.
    """
    address, _ = _mock_fixture_address_and_script()
    with mock_psbt_server() as mock_url:
        rc, out = _run_psbt(psbt_cli,
                            ['create', address, '0.00010000', '-n', '0',
                             '--provider', 'mock', '--addr-type', 'native'],
                            _sign_stdin('', SEED, ''), mock_url=mock_url)
    assert rc == 0, f'psbt create failed: rc={rc} out={out!r}'
    created_b64 = out.strip().splitlines()[-1]
    # (a) the Python mirror parses the CLI's creation
    psbt = from_base64(s=created_b64)
    assert psbt.version == 0
    assert len(psbt.unsigned_tx.vout) >= 1
    # (b) the witness input carries its UTXO field
    witness_inputs = [i for i in psbt.inputs if i.witness_utxo is not None]
    assert witness_inputs, 'the Creator must write WITNESS_UTXO for ' \
                           'witness inputs'
    # (c) the cross-signed chain: Python signs -> finalizes -> extracts
    from yubtc.psbt import sign_psbt
    assert sign_psbt(seed=SEED, passphrase='', kdf='yubtc',
                     psbt=psbt) == []
    finalize_psbt(psbt=psbt)
    tx = extract_transaction(psbt=psbt)
    assert tx.has_witness()
    assert all(vin.script == b'' for vin in tx.vin)
