#!/usr/bin/env python3

import click

from yubtc.fwd import (
    DEFAULT_CONFIRMATIONS,
    DEFAULT_FEE,
    DEFAULT_NEW_ADDRESSES,
    DEFAULT_NONCE,
    DEFAULT_SEED_WORDS,
    MINIMAL_FEE,
    TAddress,
    TAmount,
    TNonce,
    TSatoshi,
    TBTC,
)
from yubtc.net import BACKENDS, get_backend
from yubtc.wallet import Wallet
from yubtc.seed import entropy_warning, generate_seed, get_seed_and_passphrase, validate_seed
from yubtc.util import NotNone, require_kwargs_only


def _provider_names() -> str:
    """Return the comma-separated list of registered provider names."""
    return ', '.join(sorted(BACKENDS))


_STRICT_BIP39_OPTION = click.option(
    '--strict-bip39',
    help='Enforce strict BIP-39 seed validation (wordlist, checksum and entropy floor). '
         'Default: permissive -- any non-empty seed is accepted (low-entropy seeds warn).',
    default=False, required=False, is_flag=True,
)


@require_kwargs_only
def _validate_entered_seed(seed: str = NotNone, strict: bool = NotNone) -> None:
    """Reception-time seed validation for every command that accepts a
    seed (D-001 seed policy; mirrors the Rust CLI's
    prompt.rs::validate_entered_seed).

    Runs right after the seed is read and before the wallet is opened:
    `validate_seed` enforces the mode policy -- permissive (default)
    accepts any non-empty phrase, strict (CLI `--strict-bip39`) adds
    the full BIP-39 parse + C6 entropy floor as a blocking refusal --
    and the R-6 entropy-estimate warning is printed to stderr WITHOUT
    blocking when the estimate falls below `MIN_ENTROPY_WARNING_BITS`.

    Contract: `seed` is the phrase as read from the user; `strict` is
    the `--strict-bip39` flag value. Returns `None`. Raises
    `ValueError` (empty seed in either mode, or a strict-mode
    parse/entropy failure) -- the command aborts before any KDF work.
    Prints the warning to stderr when applicable; stdout stays
    machine-readable (addresses, balances). Uses `click.echo(err=True)`
    so the write is flushed before any output capture reads it back.
    """
    validate_seed(seed=seed, strict=strict)
    warning = entropy_warning(phrase=seed)
    if warning is not None:
        click.echo('warning: ' + warning, err=True)


def _resolve_provider(name: str):
    """Resolve `name` to a backend instance (backend injection: the
    result is passed explicitly into Wallet/broadcastTx; there is no
    module-global current backend).

    Catches `ValueError` from `get_backend` (unknown name) and
    re-raises with the click-friendly message pre-formatted. The CLI
    flag's `type=click.Choice` does its own validation against the
    sorted list, so in practice this only fires when the wallet is
    driven programmatically.
    """
    return get_backend(name=name)


_PROVIDER_OPTION = click.option(
    '--provider',
    help='Network provider (default: blockchain.info). Known: ' + _provider_names() + '.',
    default='blockchain.info', required=False, nargs=1,
    type=click.Choice(sorted(BACKENDS), case_sensitive=False),
)


@click.group()
def cli() -> None:
    pass


@cli.command('newseed', help='Generate new seed.')
@click.option('-n', help='Count of words (default=15).',
              default=DEFAULT_SEED_WORDS, required=False, nargs=1, type=int)
@click.option('-u', '--unique', help='Only unique words in seed.',
              default=False, required=False, is_flag=True)
def newseed(n: int, unique: bool) -> None:
    seed = generate_seed(count=n, allow_dups=not unique)
    # `newseed` prints the address derived from a freshly generated
    # seed. There is no passphrase concept here -- the seed is brand
    # new, the wallet has no funds, and the user will be asked for a
    # passphrase on the next command that opens an existing wallet.
    # Pass `''` explicitly so the decorator doesn't reject the call.
    wallet = Wallet(seed=seed, nonce=DEFAULT_NONCE,
                    new_addresses=DEFAULT_NEW_ADDRESSES, passphrase='')
    print('{seed}\r\nAddress: {address}'.format(seed=seed,
                                                address=wallet.privkeys[0].get_p2pkh_address().decode('ascii')))


@cli.command('address', help='Show native (P2PKH) address and exit.')
@click.option('-n', '--nonce', help='Scan addresses from given nonce',
              default=DEFAULT_NONCE, required=False, nargs=1, type=int)
@click.option('--new', help='Count of new unused addresses',
              default=DEFAULT_NEW_ADDRESSES, required=False, nargs=1, type=int)
@_STRICT_BIP39_OPTION
@_PROVIDER_OPTION
def address(nonce: TNonce, new: int, strict_bip39: bool, provider: str) -> None:
    backend = _resolve_provider(name=provider)
    seed, passphrase = get_seed_and_passphrase()
    _validate_entered_seed(seed=seed, strict=strict_bip39)
    wallet = Wallet(seed=seed, nonce=nonce, new_addresses=new,
                    passphrase=passphrase, backend=backend)
    print(wallet.privkeys[0].get_p2pkh_address().decode('ascii'))


@cli.command('dumpprivkey', help='Show private key in WIF format and exit.')
@click.option('-n', '--nonce', help='Scan addresses from given nonce',
              default=DEFAULT_NONCE, required=False, nargs=1, type=int)
@_STRICT_BIP39_OPTION
@_PROVIDER_OPTION
def dumpprivkey(nonce: TNonce, strict_bip39: bool, provider: str) -> None:
    backend = _resolve_provider(name=provider)
    seed, passphrase = get_seed_and_passphrase()
    _validate_entered_seed(seed=seed, strict=strict_bip39)
    wallet = Wallet(seed=seed, nonce=nonce, new_addresses=DEFAULT_NEW_ADDRESSES,
                    passphrase=passphrase, backend=backend)
    print('Address: {address}'.format(address=wallet.privkeys[0].get_p2pkh_address().decode('ascii')))
    print(wallet.privkeys[0].get_privwif().decode('ascii'))


@cli.command('balance', help='Show balance and exit.')
@click.option('-n', '--nonce', help='Scan addresses from given nonce',
              default=DEFAULT_NONCE, required=False, nargs=1, type=int)
@click.option('-c', '--confirmations', help='Minimal confirmations for inputs.',
              default=DEFAULT_CONFIRMATIONS, required=False, nargs=1, type=int)
@click.option('--new', help='Count of new unused addresses',
              default=DEFAULT_NEW_ADDRESSES, required=False, nargs=1, type=int)
@click.option('-e', '--empty', help='Show used empty addresses',
              default=False, required=False, is_flag=True)
@click.option('-v', '--verbose', help='Print verbosity',
              default=False, required=False, is_flag=True)
@_STRICT_BIP39_OPTION
@_PROVIDER_OPTION
def balance(nonce: TNonce, confirmations: int, new: int, empty: bool,
            verbose: bool, strict_bip39: bool, provider: str) -> None:
    from yubtc.misc import satoshi2btc
    backend = _resolve_provider(name=provider)
    total = TBTC(0)
    seed, passphrase = get_seed_and_passphrase()
    _validate_entered_seed(seed=seed, strict=strict_bip39)
    wallet = Wallet(seed=seed, nonce=nonce, new_addresses=new,
                    passphrase=passphrase, backend=backend)
    for privkey in wallet.privkeys:
        txs = privkey.get_unspent(confirmations=confirmations)
        in_amount = 0
        for tx in txs:
            in_amount += tx['amount']
        if not empty and in_amount == 0 and not privkey.is_unused():
            continue
        address = privkey.get_p2pkh_address().decode('ascii')
        if privkey.is_unused():
            # Never received funds -- a fresh address from the gap.
            # Distinguish it from a "used but currently empty" address
            # (which prints 0.00000000 BTC when -e is set).
            print(f'{privkey.nonce}# {address}: unused')
            continue
        amount: TBTC = satoshi2btc(in_amount)
        total += amount
        print(f'{privkey.nonce}# {address}: {amount:0.08f} BTC')
        if verbose:
            for tx in txs:
                tx_id = tx['tx']
                tx_out_n = tx['out_n']
                vin = f'({tx_id}:{tx_out_n})'
                amount = satoshi2btc(tx['amount'])
                print(f'    {vin}: {amount}')
    print(f'Total: {total:0.08f}')


@cli.command('send', help='Send BTC to address. ADDRESS - Destination address. Only P2PKH or P2SH addresses supported. '
             'AMOUNT - value to send in decimal. Set "ALL" to send all available funds.')
@click.option('-n', '--nonce', help='Scan addresses from given nonce',
              default=DEFAULT_NONCE, required=False, nargs=1, type=int)
@click.option('-c', '--confirmations', help='Minimal confirmations for inputs.',
              default=DEFAULT_CONFIRMATIONS, required=False, nargs=1, type=int)
@click.option('-f', '--fee', help='Set transaction fee. Value in decimal.',
              default=DEFAULT_FEE, required=False, nargs=1, type=TBTC)
@click.option('-k', '--feekb', help='Set fee per kilobyte (1000 bytes). Value in satoshi.',
              default=MINIMAL_FEE, required=False, nargs=1, type=int)
@click.option('--broadcast', help='Broadcast the transaction; otherwise print the raw tx to console.',
              default=False, is_flag=True)
@click.option('--scan', help='Scan addresses starting at --nonce until the target amount is reached '
              'or an unused address is found; spend all collected inputs.',
              default=False, is_flag=True)
@click.option('-i', '--interactive', help='Open an ncurses UI to pick inputs. Always scans to the '
              'gap limit; the default selection is the smallest set of UTXOs from the earliest '
              'addresses that covers the amount (and an estimated fee).',
              default=False, is_flag=True)
@click.option('-y', '--yes', help='Skip the broadcast confirmation prompt. Implies --broadcast when '
              'used in non-interactive mode; safe to combine with --broadcast explicitly.',
              default=False, is_flag=True)
@_STRICT_BIP39_OPTION
@_PROVIDER_OPTION
@click.argument('address', type=str)
@click.argument('amount', type=str)
def send(
        nonce: TNonce,
        confirmations: int,
        fee: TBTC,
        feekb: TSatoshi,
        address: TAddress,
        amount: TAmount,
        broadcast: bool,
        scan: bool,
        interactive: bool,
        yes: bool,
        strict_bip39: bool,
        provider: str) -> None:
    backend = _resolve_provider(name=provider)
    amount = None if amount == 'ALL' else TBTC(amount)
    seed, passphrase = get_seed_and_passphrase()
    _validate_entered_seed(seed=seed, strict=strict_bip39)
    wallet = Wallet(seed=seed, nonce=nonce, new_addresses=DEFAULT_NEW_ADDRESSES,
                    passphrase=passphrase, backend=backend)
    print('Address: {address}'.format(address=wallet.privkeys[0].get_p2pkh_address().decode('ascii')))

    def on_address(tp, unspent):
        from yubtc.misc import satoshi2btc
        in_amount = sum(u['amount'] for u in unspent)
        addr = tp.get_p2pkh_address().decode('ascii')
        amount_btc = satoshi2btc(in_amount)
        print(f'{tp.nonce}# {addr}: {amount_btc:0.08f} BTC')

    if interactive:
        _send_interactive(
            wallet=wallet, address=address, amount=amount,
            fee=fee, feekb=feekb, confirmations=confirmations,
            broadcast=broadcast, on_address=on_address, yes=yes,
        )
        return

    wallet.send(
        dst=address, amount=amount, fee=fee, feekb=feekb,
        confirmations=confirmations, broadcast=broadcast, scan=scan,
        on_address=on_address if scan else None, yes=yes,
    )


@require_kwargs_only
def _send_interactive(
        wallet: object = NotNone,
        address: TAddress = NotNone,
        amount=None,
        fee: TBTC = NotNone,
        feekb: TSatoshi = NotNone,
        confirmations: int = NotNone,
        broadcast: bool = NotNone,
        on_address=None,
        yes: bool = NotNone) -> None:
    """send --interactive: scan to gap, run ncurses UI, build and broadcast tx."""
    from yubtc.misc import btc2satoshi, satoshi2btc
    from yubtc.tui import run_selection
    from yubtc.select import selection_to_sources
    from yubtc.wallet import _announce_tx

    # Scan to gap (target=None) so the user sees every available UTXO.
    sources, cashback_addr = wallet._scan_inputs(
        target=None, confirmations=confirmations, on_address=on_address)
    if not sources:
        print('No funds available')
        return

    # Target the UI at exactly the requested amount (not padded with an
    # estimated fee); the UI shows the live fee impact of the user's
    # selection as they toggle inputs.
    satoshi_target = None if amount is None else btc2satoshi(amount)
    satoshi_fee = btc2satoshi(fee)

    # When the target can't be reached with the available UTXOs, no
    # selection the user could make would cover it -- skip the UI and
    # print the gap so the operator knows how short they are. Drain
    # mode (satoshi_target is None) has no target to fail against, so
    # the check is skipped.
    if satoshi_target is not None:
        total_available = sum(
            u['amount'] for pk, unspent in sources for u in unspent)
        if satoshi_target > total_available:
            print('Insufficient funds: target {target:0.08f} BTC, '
                  'available {available:0.08f} BTC'.format(
                      target=satoshi2btc(satoshi_target),
                      available=satoshi2btc(total_available)))
            return

    selected_flat = run_selection(sources, target=satoshi_target,
                                  fee=satoshi_fee, feekb=feekb,
                                  cashback_addr=cashback_addr)
    if selected_flat is None:
        print('Cancelled')
        return

    grouped = selection_to_sources(selected_flat)
    converted_amount = None if amount is None else btc2satoshi(amount)
    result = wallet.make_transaction(
        dst=address, amount=converted_amount, feekb=feekb, fee=satoshi_fee,
        confirmations=confirmations, scan=False,
        sources=grouped, cashback_addr=cashback_addr, on_address=None,
    )
    _announce_tx(backend=wallet._backend, result=result, dst=address,
                 broadcast=broadcast, yes=yes)


@cli.command('pushtx', help='Push a signed raw transaction to the network. The transaction is '
             'read from stdin as hex. The txid is computed from the raw bytes (double-SHA256, '
             'reversed) and printed before the broadcast prompt.')
@click.option('-y', '--yes', help='Skip the broadcast confirmation prompt.',
              default=False, is_flag=True)
@_PROVIDER_OPTION
def pushtx(yes: bool, provider: str) -> None:
    backend = _resolve_provider(name=provider)
    import sys
    from yubtc.hash import sha256
    from yubtc.misc import yesno
    from yubtc.net import broadcastTx

    # `input()` reads one line, leaving the rest of stdin available for
    # the confirmation prompt. `sys.stdin.read()` would consume
    # everything and the prompt would see EOF.
    try:
        rawtx_hex = input().strip()
    except EOFError:
        print('No transaction on stdin', file=sys.stderr)
        sys.exit(1)
    if not rawtx_hex:
        print('No transaction on stdin', file=sys.stderr)
        sys.exit(1)
    try:
        rawtx = bytes.fromhex(rawtx_hex)
    except ValueError as e:
        print('Invalid hex on stdin: {err}'.format(err=e), file=sys.stderr)
        sys.exit(1)

    # txid is the double-SHA256 of the serialized transaction, displayed
    # in reversed byte order (Bitcoin convention). Computed from the raw
    # bytes -- the command does not need to parse the transaction.
    txid = sha256(sha256(rawtx))[::-1].hex()
    print('id: {id}'.format(id=txid))
    print('txsize={size}'.format(size=len(rawtx)))
    print('rawtx: {rawtx}'.format(rawtx=rawtx_hex))
    if not yes and not yesno('broadcast? '):
        print('Cancelled')
        return
    broadcastTx(backend, rawtx)
