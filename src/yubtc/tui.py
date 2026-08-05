import curses
from typing import Optional

from yubtc.fwd import TSatoshi


def run_selection(
        sources,
        target: TSatoshi = None,
        fee: TSatoshi = 0,
        feekb: TSatoshi = 1000,
        cashback_addr: bytes = None):
    """Open an ncurses UI for selecting UTXOs.

    `sources`: list of (TPrivKey, unspent_list) tuples in scan order.
    `target`: total satoshi amount needed (the user's request -- not
        padded with fee). None to drain all.
    `fee`: hard-set fee in satoshi. 0 means "compute from size and feekb"
        so the live status display reflects the fee impact of the current
        input selection.
    `feekb`: fee rate in satoshi per 1000 bytes, used when `fee` is 0.
    `cashback_addr`: the address that any change (cashback) would be sent
        to. Displayed in the status line so the operator can confirm
        where leftover funds will land. Typically the first unused
        (gap-limit) address in the wallet.

    Returns a flat list of (TPrivKey, utxo_dict) in selection order, or
    None if the user cancelled.
    """
    return curses.wrapper(_loop, sources, target, fee, feekb, cashback_addr)


def _loop(stdscr, sources, target: Optional[TSatoshi],
          fee: TSatoshi = 0, feekb: TSatoshi = 1000,
          cashback_addr: bytes = None) -> Optional[list]:
    """Run the selection loop on the given screen object.

    `stdscr` is expected to provide the curses screen API: clear(),
    getmaxyx(), addnstr(y, x, str, n, *attr), getch(), refresh(),
    and befriend the curses module's A_REVERSE / KEY_* constants.
    Splitting this out from `run_selection` makes the loop testable
    without an actual terminal.
    """
    try:
        curses.curs_set(0)
    except curses.error:
        # Not running in a real terminal (e.g. redirected stdout).
        pass
    selected_set = default_selection(sources, target)
    total = compute_total(sources, selected_set)
    rows = build_rows(sources)

    cursor = _first_row(rows)
    while True:
        cur_fee, cur_size = compute_fee_and_size(
            num_inputs=len(selected_set), total=total,
            target=target, fee=fee, feekb=feekb,
        )
        render(stdscr, rows, selected_set, cursor, total, target,
               cur_fee, cur_size, cashback_addr)
        key = stdscr.getch()
        if key in (ord('q'), 27):  # q or ESC
            return None
        if key in (ord('\n'), curses.KEY_ENTER):
            return materialise(sources, selected_set)
        if key == ord(' '):
            row = rows[cursor]
            if row['kind'] == 'utxo':
                marker = (row['nonce'], row['out_n'])
                if marker in selected_set:
                    selected_set.discard(marker)
                else:
                    selected_set.add(marker)
                total = compute_total(sources, selected_set)
            else:
                # The only other row kind build_rows emits is 'addr':
                # toggle every input under that address as a group.
                target_nonce = row['nonce']
                markers = [
                    (pk.nonce, u['out_n'])
                    for pk, unspent in sources
                    if pk.nonce == target_nonce
                    for u in unspent
                ]
                # If every input in the group is already selected, treat
                # the toggle as "deselect all"; otherwise "select all" --
                # so the user can also use it to bulk-finish a partial
                # selection.
                if markers and all(m in selected_set for m in markers):
                    for m in markers:
                        selected_set.discard(m)
                else:
                    for m in markers:
                        selected_set.add(m)
                total = compute_total(sources, selected_set)
        elif key == ord('a'):
            for pk, unspent in sources:
                for u in unspent:
                    selected_set.add((pk.nonce, u['out_n']))
            total = compute_total(sources, selected_set)
        elif key == ord('n'):
            selected_set.clear()
            total = 0
        elif key in (curses.KEY_DOWN, ord('j')):
            cursor = _step(rows, cursor, +1)
        elif key in (curses.KEY_UP, ord('k')):
            cursor = _step(rows, cursor, -1)


def default_selection(sources, target: Optional[TSatoshi]) -> set:
    """Greedy default: smallest set from earliest addresses that meets target.

    See module-level docstring on `run_selection` for the parameter
    contract. Kept as a module-level function so it can be unit-tested
    without invoking curses.
    """
    selected = set()
    if not sources:
        return selected
    total = 0
    for pk, unspent in sources:
        if target is not None and total >= target:
            break
        for u in unspent:
            selected.add((pk.nonce, u['out_n']))
            total += u['amount']
            if target is not None and total >= target:
                break
    return selected


def compute_total(sources, selected_set: set) -> int:
    """Sum the amounts of all UTXOs marked in `selected_set`."""
    total = 0
    for pk, unspent in sources:
        for u in unspent:
            if (pk.nonce, u['out_n']) in selected_set:
                total += u['amount']
    return total


def estimate_tx_size(num_inputs: int, num_outputs: int) -> int:
    """Rough estimate of a P2PKH-only tx size in bytes.

    ~10 bytes of tx overhead, ~148 bytes per P2PKH input (DER sig +
    compressed pubkey + push op + txin scaffolding), ~34 bytes per
    P2PKH output (amount + script length + P2PKH script). Good enough
    for the UI's live fee readout -- the precise fee is recomputed when
    make_transaction actually signs the tx.
    """
    return 10 + 148 * num_inputs + 34 * num_outputs


def _count_outputs(total: int, target: Optional[TSatoshi],
                   fee: TSatoshi) -> int:
    """Number of outputs: 1 (dst only) or 2 (dst + cashback).

    Cashback is needed when target is set and the inputs exceed target
    + fee (the user is sending a fixed amount and has leftover). In
    drain mode (target is None) the whole input minus fee goes to dst,
    so there's no cashback output.
    """
    if target is None:
        return 1
    if total <= target + fee:
        return 1
    return 2


def compute_fee_and_size(num_inputs: int, total: int,
                         target: Optional[TSatoshi], fee: TSatoshi,
                         feekb: TSatoshi) -> tuple:
    """Return (fee, size_in_bytes) reflecting the current selection.

    When `fee` (the hard-set fee) is non-zero, it's returned unchanged
    -- the operator pinned it and we just display it. Otherwise the
    fee is computed from the estimated tx size and `feekb`, so the
    status line updates live as inputs are toggled.
    """
    num_outputs = _count_outputs(total, target, fee)
    size = estimate_tx_size(num_inputs, num_outputs)
    if fee:
        return fee, size
    return size * feekb // 1000, size


def build_rows(sources) -> list:
    """Flatten (sources, UTXOs) into a list of dicts the renderer can use.

    Two row kinds: 'addr' (header) and 'utxo' (selectable). UTXO rows
    carry the underlying utxo dict so the renderer can show amount.
    """
    rows = []
    for pk, unspent in sources:
        addr = pk.get_p2pkh_address()
        rows.append({'kind': 'addr', 'nonce': pk.nonce, 'addr': addr})
        for u in unspent:
            rows.append({
                'kind': 'utxo', 'nonce': pk.nonce, 'addr': addr,
                'out_n': u['out_n'], 'utxo': u,
            })
    return rows


def materialise(sources, selected_set: set) -> list:
    """Convert the (nonce, out_n) selection back to a flat list of (pk, utxo)."""
    result = []
    for pk, unspent in sources:
        for u in unspent:
            if (pk.nonce, u['out_n']) in selected_set:
                result.append((pk, u))
    return result


def render(stdscr, rows: list, selected_set: set, cursor: int,
           total: int, target: Optional[TSatoshi],
           fee: TSatoshi, size: int,
           cashback_addr: bytes = None) -> None:
    """Draw the selection UI to the screen."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    last_data_row = max(0, h - 3)
    for i, row in enumerate(rows):
        if i > last_data_row:
            break
        line = format_row(row, selected_set, w)
        attr = curses.A_REVERSE if i == cursor else 0
        stdscr.addnstr(i, 0, line, w - 1, attr)
    if h >= 2:
        stdscr.addnstr(
            h - 2, 0,
            format_status(total, target, fee, size,
                          cashback_addr=cashback_addr),
            w - 1,
        )
    if h >= 1:
        help_text = '[Space]=toggle [a]=all [n]=none [Enter]=ok [q]=cancel'
        stdscr.addnstr(h - 1, 0, help_text, w - 1)
    stdscr.refresh()


def format_row(row: dict, selected_set: set, width: int) -> str:
    """Render a single row (address header or UTXO)."""
    from yubtc.misc import satoshi2btc
    addr = row['addr']
    if isinstance(addr, bytes):
        addr = addr.decode('ascii')
    if row['kind'] == 'addr':
        return f'  {row["nonce"]}# {addr}'
    checked = '[x]' if (row['nonce'], row['out_n']) in selected_set else '[ ]'
    amount = satoshi2btc(row['utxo']['amount'])
    return f'    {checked} ({row["utxo"]["tx"]}:{row["out_n"]}) {amount:0.08f} BTC'


def format_status(total: int, target: Optional[TSatoshi],
                  fee: TSatoshi, size: int,
                  cashback_addr: bytes = None) -> str:
    """Render the bottom status line.

    Layout (target mode):

        <m1>Selected: total/target <m2>Target: target/required
        fee=<btc> size=<bytes>B cashback=<btc> cashbackaddr=<addr>

    where m1 is ✓ when total >= target (selection covers the amount) and
    m2 is ✓ when total >= required (selection also covers the fee). The
    chain total >= target >= required reads naturally left-to-right.
    `cashback` is the change that would land back at the cashback
    address; 0 when there's no leftover (or in drain mode, where
    everything minus fee goes to dst). `cashbackaddr` is the destination
    for that change -- typically the first unused (gap-limit) address.

    In drain mode (target=None) the Target/Required segments are
    omitted and "Selected" reads as a flat balance. `cashbackaddr` is
    always shown when provided so the operator can confirm where the
    fee is paid from.
    """
    from yubtc.misc import satoshi2btc
    fee_btc = satoshi2btc(fee)
    if target is None:
        cashback = 0
    elif total >= target + fee:
        cashback = total - target - fee
    else:
        cashback = 0
    cashback_btc = satoshi2btc(cashback)
    addr_str = ''
    if cashback_addr is not None:
        addr = cashback_addr
        if isinstance(addr, bytes):
            addr = addr.decode('ascii')
        addr_str = f' cashbackaddr={addr}'
    if target is None:
        return (f'Selected: {satoshi2btc(total):0.08f} BTC (drain) '
                f'fee={fee_btc:0.08f} size={size}B '
                f'cashback={cashback_btc:0.08f}{addr_str}')
    required = target + fee
    m1 = '✓' if total >= target else ''
    m2 = '✓' if total >= required else ''
    return (f'{m1}Selected: {satoshi2btc(total):0.08f}/'
            f'{satoshi2btc(target):0.08f} '
            f'{m2}Target: {satoshi2btc(target):0.08f}/'
            f'{satoshi2btc(required):0.08f} '
            f'fee={fee_btc:0.08f} size={size}B '
            f'cashback={cashback_btc:0.08f}{addr_str}')


def _first_row(rows: list) -> int:
    """Initial cursor position -- the first row, or 0 if there are none."""
    return 0 if rows else 0


def _step(rows: list, cursor: int, direction: int) -> int:
    """Move the cursor by `direction` rows, clamped to bounds.

    Both address and UTXO rows are reachable; Space is a no-op on
    address rows. If the new position is out of range, the cursor
    stays put.
    """
    n = len(rows)
    new_cursor = cursor + direction
    if 0 <= new_cursor < n:
        return new_cursor
    return cursor
