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
        scan: bool) -> None:
    amount = None if amount == 'ALL' else TBTC(amount)
    wallet = Wallet(seed=get_seed(), nonce=nonce, new_addresses=DEFAULT_NEW_ADDRESSES)
    print('Address: {address}'.format(address=wallet.privkeys[0].get_p2pkh_address().decode('ascii')))

    def on_address(tp, unspent):
        from yubtc.misc import satoshi2btc
        in_amount = sum(u['amount'] for u in unspent)
        addr = tp.get_p2pkh_address().decode('ascii')
        amount_btc = satoshi2btc(in_amount)
        print(f'{tp.nonce}# {addr}: {amount_btc:0.08f} BTC')

    wallet.send(
        dst=address, amount=amount, fee=fee, feekb=feekb,
        confirmations=confirmations, broadcast=broadcast, scan=scan,
        on_address=on_address if scan else None,
    )
