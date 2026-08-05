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
from yubtc.wallet import Wallet
from yubtc.seed import generate_seed, get_seed
from yubtc.util import NotNone, require_kwargs_only


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
    wallet = Wallet(seed=seed, nonce=DEFAULT_NONCE,
                    new_addresses=DEFAULT_NEW_ADDRESSES)
    print('{seed}\r\nAddress: {address}'.format(seed=seed,
                                                address=wallet.privkeys[0].get_p2pkh_address().decode('ascii')))


@cli.command('address', help='Show native (P2PKH) address and exit.')
@click.option('-n', '--nonce', help='Scan addresses from given nonce',
              default=DEFAULT_NONCE, required=False, nargs=1, type=int)
@click.option('--new', help='Count of new unused addresses',
              default=DEFAULT_NEW_ADDRESSES, required=False, nargs=1, type=int)
def address(nonce: TNonce, new: int) -> None:
    wallet = Wallet(seed=get_seed(), nonce=nonce, new_addresses=new)
    print(wallet.privkeys[0].get_p2pkh_address().decode('ascii'))


@cli.command('dumpprivkey', help='Show private key in WIF format and exit.')
@click.option('-n', '--nonce', help='Scan addresses from given nonce',
              default=DEFAULT_NONCE, required=False, nargs=1, type=int)
def dumpprivkey(nonce: TNonce) -> None:
    wallet = Wallet(seed=get_seed(), nonce=nonce, new_addresses=DEFAULT_NEW_ADDRESSES)
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
def balance(nonce: TNonce, confirmations: int, new: int, empty: bool, verbose: bool) -> None:
    from yubtc.misc import satoshi2btc
    total = TBTC(0)
    wallet = Wallet(seed=get_seed(), nonce=nonce, new_addresses=new)
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
        interactive: bool) -> None:
    amount = None if amount == 'ALL' else TBTC(amount)
    wallet = Wallet(seed=get_seed(), nonce=nonce, new_addresses=DEFAULT_NEW_ADDRESSES)
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
            broadcast=broadcast, on_address=on_address,
        )
        return

    wallet.send(
        dst=address, amount=amount, fee=fee, feekb=feekb,
        confirmations=confirmations, broadcast=broadcast, scan=scan,
        on_address=on_address if scan else None,
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
        on_address=None) -> None:
    """send --interactive: scan to gap, run ncurses UI, build and broadcast tx."""
    from yubtc.misc import btc2satoshi, satoshi2btc, yesno
    from yubtc.net import sendTx
    from yubtc.tui import run_selection
    from yubtc.select import selection_to_sources

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
    cashback_btc = satoshi2btc(result.cashback)
    sent_btc = satoshi2btc(result.amount)
    fee_btc = satoshi2btc(result.fee)
    rawtx = result.tx.serialize()
    print('id: {id}'.format(id=result.tx.id().hex()))
    print('send {amount:0.08f} BTC to {dst} (cashback={cashback:0.08f}, fee={fee:0.08f}, txsize={txsize})'.format(
        amount=sent_btc, dst=address, cashback=cashback_btc, fee=fee_btc,
        txsize=len(rawtx)))
    print('rawtx: {rawtx}'.format(rawtx=rawtx.hex()))
    if broadcast:
        if yesno('broadcast? '):
            sendTx(rawtx)
