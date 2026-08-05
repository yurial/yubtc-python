import curses

from yubtc.tui import (
    _count_outputs,
    _loop,
    _step,
    _first_row,
    build_rows,
    compute_fee_and_size,
    compute_total,
    default_selection,
    estimate_tx_size,
    format_row,
    format_status,
    materialise,
    render,
)


def _fake_pk(nonce, addr=None):
    """Build a fake TPrivKey for tests; the loop only reads .nonce and
    .get_p2pkh_address()."""
    class FakePk:
        def get_p2pkh_address(self):
            return (addr or f'addr-{nonce}').encode('ascii')
    p = FakePk()
    p.nonce = nonce
    return p


class MockScreen:
    """Minimal curses-screen stand-in for testing _loop without a TTY.

    Records every addnstr() call and feeds getch() from a pre-canned
    key queue. getmaxyx() returns a fixed (rows, cols) so the renderer's
    bounds are deterministic.
    """

    def __init__(self, keys, h=24, w=80):
        self._keys = list(keys)
        self._h = h
        self._w = w
        self.drawn = []
        self.refresh_count = 0

    def getmaxyx(self):
        return (self._h, self._w)

    def clear(self):
        pass

    def addnstr(self, y, x, s, n, *attr):
        self.drawn.append((y, x, s, attr))

    def getch(self):
        return self._keys.pop(0)

    def refresh(self):
        self.refresh_count += 1


def _sources_with_utxos(specs):
    """Build a sources list from {nonce: [amount, ...]}.

    out_n is the position in the UTXO list; txid is a dummy hash.
    """
    out = []
    for nonce, amounts in specs.items():
        unspent = [
            {'tx': f'{nonce:02x}{i:062x}', 'out_n': i, 'amount': a,
             'confirmations': 10, 'script': '76a914' + 'aa' * 20 + '88ac'}
            for i, a in enumerate(amounts)
        ]
        out.append((_fake_pk(nonce), unspent))
    return out


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_build_rows_makes_addr_and_utxo_rows():
    sources = _sources_with_utxos({0: [100, 200]})
    rows = build_rows(sources)
    # 1 address header + 2 UTXOs.
    assert len(rows) == 3
    assert rows[0]['kind'] == 'addr'
    assert rows[0]['nonce'] == 0
    assert rows[1]['kind'] == 'utxo'
    assert rows[1]['out_n'] == 0
    assert rows[1]['utxo']['amount'] == 100
    assert rows[2]['kind'] == 'utxo'
    assert rows[2]['out_n'] == 1
    assert rows[2]['utxo']['amount'] == 200


def test_build_rows_empty_sources():
    assert build_rows([]) == []


def test_compute_total_sums_selected():
    sources = _sources_with_utxos({0: [100, 200], 1: [50]})
    assert compute_total(sources, set()) == 0
    assert compute_total(sources, {(0, 0), (0, 1)}) == 300
    assert compute_total(sources, {(1, 0)}) == 50


def test_default_selection_via_tui_module_matches():
    """Module-level default_selection is a duplicate of the package one
    so the loop can be tested without going through the package import.
    """
    sources = _sources_with_utxos({0: [100], 1: [400]})
    assert default_selection(sources, target=450) == {(0, 0), (1, 0)}


def test_materialise_returns_flat_list_for_selection():
    sources = _sources_with_utxos({0: [100, 200]})
    selected = {(0, 0), (0, 1)}
    result = materialise(sources, selected)
    amounts = sorted(u['amount'] for _, u in result)
    assert amounts == [100, 200]


def test_materialise_skips_unselected():
    sources = _sources_with_utxos({0: [100, 200]})
    result = materialise(sources, {(0, 0)})
    assert len(result) == 1
    assert result[0][1]['amount'] == 100


def test_format_row_address_kind():
    row = {'kind': 'addr', 'nonce': 0, 'addr': b'1ABC'}
    assert format_row(row, set(), 80) == '  0# 1ABC'


def test_format_row_utxo_selected():
    row = {
        'kind': 'utxo', 'nonce': 0, 'addr': '1ABC',
        'out_n': 2, 'utxo': {'tx': 'a' * 64, 'amount': 1234},
    }
    assert format_row(row, {(0, 2)}, 80) == (
        f'    [x] ({"a" * 64}:2) 0.00001234 BTC'
    )


def test_format_row_utxo_not_selected():
    row = {
        'kind': 'utxo', 'nonce': 0, 'addr': '1ABC',
        'out_n': 2, 'utxo': {'tx': 'a' * 64, 'amount': 1234},
    }
    assert format_row(row, set(), 80) == (
        f'    [ ] ({"a" * 64}:2) 0.00001234 BTC'
    )


def test_format_status_drain():
    """target=None -> '(drain)' suffix, no Target/Required, cashback=0."""
    line = format_status(50_000, None, fee=1_000, size=192)
    assert '(drain)' in line
    assert 'Target' not in line
    assert 'cashback=0.00000000' in line
    assert 'fee=0.00001000' in line
    assert 'size=192B' in line


def test_format_status_cashback_addr_appended_when_provided():
    """The cashback address is appended after cashback=<btc>."""
    addr = b'1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k'
    line = format_status(50_000, target=10_000, fee=1_000, size=192,
                         cashback_addr=addr)
    assert line.endswith('cashbackaddr=1NHD3xcMHK7QW1bPQq1J5SCb6cpbMsCX7k')


def test_format_status_cashback_addr_omitted_when_none():
    """No cashbackaddr segment when cashback_addr is None."""
    line = format_status(50_000, target=10_000, fee=1_000, size=192,
                         cashback_addr=None)
    assert 'cashbackaddr' not in line


def test_format_status_cashback_addr_accepts_str():
    """cashback_addr can also be passed as a str (already decoded)."""
    line = format_status(50_000, target=10_000, fee=1_000, size=192,
                         cashback_addr='1ABC')
    assert 'cashbackaddr=1ABC' in line


def test_format_status_cashback_addr_works_in_drain_mode():
    """cashbackaddr is shown in drain mode too (so the operator can
    confirm where the fee is paid from)."""
    line = format_status(50_000, None, fee=1_000, size=192,
                         cashback_addr=b'1ABC')
    assert 'cashbackaddr=1ABC' in line


def test_format_status_target_no_checkmarks_when_below():
    """total < target -> no ✓ marks."""
    # total=9_999, target=10_000, fee=1_000 -> required=11_000.
    line = format_status(9_999, target=10_000, fee=1_000, size=192)
    assert line.startswith('Selected: ')
    assert '✓' not in line
    # Total/target shown in the Selected segment; Target segment shows
    # target/required=10_000/11_000.
    assert 'Target: 0.00010000/0.00011000' in line
    assert 'cashback=0.00000000' in line


def test_format_status_first_mark_when_total_equals_target():
    """total == target -> only the first ✓ (required > target because fee > 0)."""
    # total=10_000, target=10_000, fee=1_000 -> required=11_000.
    # 10_000 >= 10_000 True; 10_000 >= 11_000 False.
    line = format_status(10_000, target=10_000, fee=1_000, size=192)
    assert line.startswith('✓Selected: 0.00010000/0.00010000 ')
    assert ' Target: 0.00010000/0.00011000 ' in line
    assert '✓Target:' not in line


def test_format_status_first_only_mark_when_between_target_and_required():
    """target < total < required -> only the first ✓."""
    # total=10_500, target=10_000, fee=1_000 -> required=11_000.
    line = format_status(10_500, target=10_000, fee=1_000, size=192)
    assert line.startswith('✓Selected: 0.00010500/0.00010000 ')
    assert ' Target: 0.00010000/0.00011000 ' in line
    assert '✓Target:' not in line


def test_format_status_second_mark_when_total_equals_required():
    """total == required -> both ✓ marks."""
    # total=11_000, target=10_000, fee=1_000 -> required=11_000.
    line = format_status(11_000, target=10_000, fee=1_000, size=192)
    assert line.startswith('✓Selected: 0.00011000/0.00010000 ')
    assert ' ✓Target: 0.00010000/0.00011000 ' in line


def test_format_status_both_marks_when_above_required():
    """total > required -> both ✓ marks."""
    # total=50_000, target=10_000, fee=1_000 -> required=11_000.
    line = format_status(50_000, target=10_000, fee=1_000, size=192)
    assert line.startswith('✓Selected: 0.00050000/0.00010000 ')
    assert ' ✓Target: 0.00010000/0.00011000 ' in line


def test_format_status_required_equals_target_plus_fee():
    """Required is target + fee, displayed with satoshi precision."""
    line = format_status(0, target=7_777, fee=333, size=192)
    assert 'Target: 0.00007777/0.00008110' in line  # 7_777 + 333 = 8_110


def test_format_status_cashback_is_leftover_after_target_and_fee():
    """cashback = total - target - fee when total > target + fee."""
    # total=50_000, target=10_000, fee=1_000 -> cashback=39_000.
    line = format_status(50_000, target=10_000, fee=1_000, size=192)
    assert 'cashback=0.00039000' in line


def test_format_status_cashback_zero_when_no_leftover():
    """cashback=0 when total <= target + fee."""
    line = format_status(11_000, target=10_000, fee=1_000, size=192)
    assert 'cashback=0.00000000' in line


def test_format_status_cashback_zero_in_drain_mode():
    """In drain mode there's no cashback; cashback reads as 0."""
    line = format_status(50_000, None, fee=1_000, size=192)
    assert 'cashback=0.00000000' in line


def test_first_row_returns_zero():
    rows = [
        {'kind': 'addr', 'nonce': 0},
        {'kind': 'utxo', 'nonce': 0, 'out_n': 0},
        {'kind': 'utxo', 'nonce': 0, 'out_n': 1},
    ]
    assert _first_row(rows) == 0


def test_first_row_empty_returns_zero():
    assert _first_row([]) == 0


def test_step_down_moves_to_any_row():
    """_step moves to the next row regardless of kind."""
    rows = [
        {'kind': 'addr', 'nonce': 0},
        {'kind': 'utxo', 'nonce': 0, 'out_n': 0},
        {'kind': 'addr', 'nonce': 1},
        {'kind': 'utxo', 'nonce': 1, 'out_n': 0},
    ]
    # +1 lands on the address row (idx 2) — no special-skipping.
    assert _step(rows, 1, +1) == 2
    assert _step(rows, 0, +1) == 1
    assert _step(rows, 2, +1) == 3


def test_step_up_moves_to_any_row():
    rows = [
        {'kind': 'addr', 'nonce': 0},
        {'kind': 'utxo', 'nonce': 0, 'out_n': 0},
        {'kind': 'addr', 'nonce': 1},
        {'kind': 'utxo', 'nonce': 1, 'out_n': 0},
    ]
    assert _step(rows, 3, -1) == 2
    assert _step(rows, 2, -1) == 1
    assert _step(rows, 1, -1) == 0


def test_step_at_boundary_stays():
    rows = [
        {'kind': 'addr', 'nonce': 0},
        {'kind': 'utxo', 'nonce': 0, 'out_n': 0},
    ]
    # No row above the top.
    assert _step(rows, 0, -1) == 0
    # No row below the bottom.
    assert _step(rows, 1, +1) == 1


# ---------------------------------------------------------------------------
# render() -- exercises the bounds branches.
# ---------------------------------------------------------------------------


def test_render_draws_all_rows_then_status_and_help():
    sources = _sources_with_utxos({0: [100], 1: [200]})
    rows = build_rows(sources)
    screen = MockScreen([])
    render(screen, rows, set(), 0, 0, target=1000, fee=1_000, size=340)
    # 1 addr + 2 utxos = 3 data rows; status and help on the last two.
    ys = sorted({d[0] for d in screen.drawn})
    assert 0 in ys and 1 in ys and 2 in ys
    assert max(ys) == 23  # last row of a 24-high screen (help text)


def test_render_truncates_data_rows_on_small_screen():
    sources = _sources_with_utxos({0: [100], 1: [200]})
    rows = build_rows(sources)
    # Tiny screen: only the first data row fits; status/help still drawn.
    screen = MockScreen([], h=4, w=80)
    render(screen, rows, set(), 0, 0, target=None, fee=0, size=192)
    ys = sorted({d[0] for d in screen.drawn})
    assert max(ys) <= 3
    # Status is at h-2=2.
    assert 2 in ys
    # Help at h-1=3.
    assert 3 in ys


def test_render_uses_reverse_attr_on_cursor_row():
    sources = _sources_with_utxos({0: [100]})
    rows = build_rows(sources)
    screen = MockScreen([])
    render(screen, rows, set(), cursor=0, total=0, target=100,
           fee=1_000, size=192)
    cursor_draws = [d for d in screen.drawn if d[0] == 0 and d[3]]
    assert cursor_draws and curses.A_REVERSE in cursor_draws[0][3]


def test_render_no_status_or_help_when_screen_too_short():
    sources = _sources_with_utxos({0: [100]})
    rows = build_rows(sources)
    # h=1 -> no room for status/help lines (indices -2 and -1 wrap).
    screen = MockScreen([], h=1, w=80)
    render(screen, rows, set(), 0, 0, target=None, fee=0, size=192)
    # Only the data row appears.
    assert all(d[0] == 0 for d in screen.drawn)


# ---------------------------------------------------------------------------
# _loop -- key handling
# ---------------------------------------------------------------------------


def test_loop_q_returns_none():
    sources = _sources_with_utxos({0: [100]})
    screen = MockScreen([ord('q')])
    assert _loop(screen, sources, target=100) is None


def test_loop_esc_returns_none():
    sources = _sources_with_utxos({0: [100]})
    screen = MockScreen([27])
    assert _loop(screen, sources, target=100) is None


def test_loop_enter_returns_materialised_selection():
    sources = _sources_with_utxos({0: [100, 200]})
    # target=150: greedy selects (0,0)=100 first, then (0,1)=200 (total 300 >= 150).
    # Cursor starts at row 0 (address). Enter confirms the default
    # selection.
    screen = MockScreen([ord('\n')])
    result = _loop(screen, sources, target=150)
    assert result is not None
    pk, utxo = result[0]
    assert pk.nonce == 0
    assert utxo['out_n'] == 0


def test_loop_keypad_enter_also_confirms():
    sources = _sources_with_utxos({0: [100]})
    # Cursor on address row; Enter confirms the default selection.
    screen = MockScreen([curses.KEY_ENTER])
    result = _loop(screen, sources, target=None)
    assert result is not None
    assert result[0][1]['amount'] == 100


def test_loop_space_on_utxo_row_toggles_selection():
    """DOWN to UTXO row, then space toggles it off."""
    sources = _sources_with_utxos({0: [100]})
    screen = MockScreen([curses.KEY_DOWN, ord(' '), ord('\n')])
    result = _loop(screen, sources, target=None)
    # Toggled off -> empty selection.
    assert result == []


def test_loop_space_on_address_row_with_all_selected_deselects_group():
    """Cursor on an address row where every input is selected: Space
    deselects them all (so the operator can wipe a whole group at once)."""
    sources = _sources_with_utxos({0: [100, 200]})
    # target=10000 (drain) -> default selected everything.
    screen = MockScreen([ord(' '), ord('\n')])
    result = _loop(screen, sources, target=10_000)
    assert result == []


def test_loop_space_on_address_row_with_none_selected_selects_group():
    """Cursor on an address row where no input is selected: Space
    selects every input in that group."""
    sources = _sources_with_utxos({0: [100, 200]})
    # target=100 -> default selected only (0,0); cursor starts on row 0
    # (the address row). Pressing Space should select every input in
    # the group, not just toggle (0,0).
    screen = MockScreen([ord(' '), ord('\n')])
    result = _loop(screen, sources, target=100)
    assert result is not None
    out_ns = sorted(u['out_n'] for _, u in result)
    assert out_ns == [0, 1]


def test_loop_space_on_address_row_with_partial_selection_selects_remaining():
    """Cursor on an address row with a partial selection: Space
    bulk-selects the unselected inputs (rather than being a no-op)."""
    sources = _sources_with_utxos({0: [100, 200, 300]})
    # Manually pre-select only (0,0) by walking down to row 1 and
    # then back up to row 0. The default already pre-selected only
    # (0,0) for target=100, so no manual work is needed.
    screen = MockScreen([ord(' '), ord('\n')])
    result = _loop(screen, sources, target=100)
    out_ns = sorted(u['out_n'] for _, u in result)
    assert out_ns == [0, 1, 2]


def test_loop_space_on_address_row_with_empty_group_is_noop():
    """Cursor on an address row whose group has no inputs: Space is
    a no-op (no markers exist to toggle)."""
    sources = [
        (_fake_pk(0), []),  # no UTXOs at all
    ]
    screen = MockScreen([ord(' '), ord('\n')])
    result = _loop(screen, sources, target=None)
    assert result == []


def test_loop_space_adds_unselected_utxo():
    """Toggle ON path: cursor on an unselected UTXO adds it."""
    sources = _sources_with_utxos({0: [100, 200]})
    # target=100 -> default selects only (0,0). Move down twice (addr,
    # utxo) to (0,1) and toggle on.
    screen = MockScreen([curses.KEY_DOWN, curses.KEY_DOWN, ord(' '), ord('\n')])
    result = _loop(screen, sources, target=100)
    assert result is not None
    out_ns = sorted(u['out_n'] for _, u in result)
    assert out_ns == [0, 1]


def test_loop_a_selects_all():
    sources = _sources_with_utxos({0: [100], 1: [200]})
    # Start with target=10000 -> default selection is everything.
    # Press 'n' first to clear, then 'a' to add all, then enter.
    screen = MockScreen([ord('n'), ord('a'), ord('\n')])
    result = _loop(screen, sources, target=10_000)
    assert len(result) == 2


def test_loop_n_selects_none():
    sources = _sources_with_utxos({0: [100], 1: [200]})
    # Default selection covers target=10_000 -> everything. Press 'n' to
    # deselect all, then enter.
    screen = MockScreen([ord('n'), ord('\n')])
    result = _loop(screen, sources, target=10_000)
    assert result == []


def test_loop_down_moves_cursor():
    """Cursor moves down through both address and UTXO rows."""
    sources = _sources_with_utxos({0: [100], 1: [200]})
    # Rows: [a0, u0, a1, u1]. Cursor starts at 0.
    # DOWN -> 1 (UTXO 0). DOWN -> 2 (addr 1). DOWN -> 3 (UTXO 1).
    # Space toggles u1 off. Enter confirms: only u0 remains.
    screen = MockScreen([curses.KEY_DOWN, curses.KEY_DOWN, curses.KEY_DOWN,
                         ord(' '), ord('\n')])
    result = _loop(screen, sources, target=None)
    assert result is not None
    nonces = [pk.nonce for pk, _ in result]
    assert nonces == [0]


def test_loop_down_does_not_move_past_last_row():
    """At the last row, KEY_DOWN keeps the cursor in place."""
    sources = _sources_with_utxos({0: [100], 1: [200]})
    # Move to the last row (3) and press DOWN a few more times. Cursor
    # stays at 3; toggling off u1 leaves only u0 selected.
    screen = MockScreen([curses.KEY_DOWN, curses.KEY_DOWN, curses.KEY_DOWN,
                         curses.KEY_DOWN, curses.KEY_DOWN,
                         ord(' '), ord('\n')])
    result = _loop(screen, sources, target=None)
    nonces = [pk.nonce for pk, _ in result]
    assert nonces == [0]


def test_loop_j_k_act_like_arrow_keys():
    sources = _sources_with_utxos({0: [100], 1: [200]})
    # 'j' = down, 'k' = up. From row 0: j -> 1 (UTXO 0). k -> 0 (back).
    # Enter confirms default.
    screen = MockScreen([ord('j'), ord('k'), ord('\n')])
    result = _loop(screen, sources, target=None)
    assert result is not None


def test_loop_cursor_bounds_on_up():
    sources = _sources_with_utxos({0: [100]})
    # Cursor starts at row 0 (top). Pressing UP keeps it at 0.
    screen = MockScreen([curses.KEY_UP, curses.KEY_UP, ord('\n')])
    result = _loop(screen, sources, target=None)
    assert result is not None


def test_loop_cursor_bounds_on_down():
    sources = _sources_with_utxos({0: [100]})
    # Cursor starts at row 0; DOWN -> 1 (UTXO). DOWN again -> stays at 1.
    # Toggle, confirm.
    screen = MockScreen([curses.KEY_DOWN, curses.KEY_DOWN, ord(' '), ord('\n')])
    result = _loop(screen, sources, target=None)
    assert result == []


def test_loop_unhandled_key_is_ignored():
    sources = _sources_with_utxos({0: [100]})
    # 'x' is not bound; loop should keep going.
    screen = MockScreen([ord('x'), ord('\n')])
    result = _loop(screen, sources, target=None)
    assert result is not None


def test_loop_handles_empty_sources():
    # No sources at all -> no rows; pressing enter exits immediately.
    screen = MockScreen([ord('\n')])
    result = _loop(screen, [], target=1000)
    assert result == []


def test_loop_calls_curs_set_smoke(monkeypatch):
    """The loop calls curses.curs_set(0); mock it so the test doesn't
    need a real terminal, but still cover the line."""
    import yubtc.tui as tui_mod
    monkeypatch.setattr(tui_mod.curses, 'curs_set', lambda n: None)
    sources = _sources_with_utxos({0: [100]})
    screen = MockScreen([ord('\n')])
    _loop(screen, sources, target=None)


def test_loop_curs_set_swallows_error(monkeypatch):
    """Some terminals reject curs_set; the loop must swallow the error."""
    import yubtc.tui as tui_mod

    def boom(n):
        raise tui_mod.curses.error
    monkeypatch.setattr(tui_mod.curses, 'curs_set', boom)
    sources = _sources_with_utxos({0: [100]})
    screen = MockScreen([ord('\n')])
    result = _loop(screen, sources, target=None)
    assert result is not None


def test_render_no_help_when_screen_height_zero():
    """A zero-height screen skips the help line; status line also skipped."""
    sources = _sources_with_utxos({0: [100]})
    rows = build_rows(sources)
    # h=0 -> both h>=1 and h>=2 are False -> only data rows on row 0.
    # But row 0 is also the "last_data_row" cutoff (max(0, h-3)=0), so
    # one data row is still drawn at y=0.
    screen = MockScreen([], h=0, w=80)
    render(screen, rows, set(), 0, 0, target=None, fee=0, size=192)
    ys = sorted({d[0] for d in screen.drawn})
    # No status (y=-2 wraps) or help (y=-1 wraps) lines drawn.
    assert 0 in ys
    # Exactly one row drawn.
    assert len(screen.drawn) == 1


def test_default_selection_outer_break_fires():
    """When target is already met before entering an address, the outer
    break (line 81 of tui.py) fires and that address is skipped."""
    sources = [
        (_fake_pk(0), [{'out_n': 0, 'amount': 100}]),
        (_fake_pk(1), [{'out_n': 0, 'amount': 50}]),
    ]
    # target=80: pk0 adds (0,0) for total=100 >= 80 (inner break).
    # Outer loop iteration pk1: total=100 >= 80 -> outer break fires.
    selected = default_selection(sources, target=80)
    assert selected == {(0, 0)}


# ---------------------------------------------------------------------------
# estimate_tx_size / _count_outputs / compute_fee_and_size -- the live
# fee math that feeds the status line.
# ---------------------------------------------------------------------------


def test_estimate_tx_size_one_input_one_output():
    # 10 + 148*1 + 34*1 = 192.
    assert estimate_tx_size(1, 1) == 192


def test_estimate_tx_size_grows_with_inputs_and_outputs():
    # Two inputs / two outputs (cashback present) -> 10 + 296 + 68 = 374.
    assert estimate_tx_size(2, 2) == 374
    # Three inputs / one output (drain) -> 10 + 444 + 34 = 488.
    assert estimate_tx_size(3, 1) == 488


def test_count_outputs_no_cashback_in_drain_mode():
    # target=None -> always 1 output (the whole input minus fee goes to dst).
    assert _count_outputs(total=1_000_000, target=None, fee=1_000) == 1


def test_count_outputs_no_cashback_when_inputs_cover_target_exactly():
    # total == target + fee -> nothing left over, 1 output.
    assert _count_outputs(total=11_000, target=10_000, fee=1_000) == 1


def test_count_outputs_cashback_when_inputs_exceed_target():
    # total > target + fee -> leftover, 2 outputs (dst + cashback).
    assert _count_outputs(total=15_000, target=10_000, fee=1_000) == 2


def test_compute_fee_and_size_uses_hard_fee_when_set():
    """Hard-set fee is returned unchanged; size still reflects selection."""
    fee, size = compute_fee_and_size(
        num_inputs=2, total=50_000, target=10_000, fee=2_500, feekb=1000,
    )
    assert fee == 2_500
    # 2 inputs + 2 outputs (cashback) -> 10 + 296 + 68 = 374.
    assert size == 374


def test_compute_fee_and_size_derives_fee_from_feekb_when_unset():
    """fee=0 means compute: fee = size * feekb // 1000."""
    fee, size = compute_fee_and_size(
        num_inputs=1, total=50_000, target=10_000, fee=0, feekb=2000,
    )
    # 1 input, no cashback (target+fee=10_000+0... fee unknown yet).
    # First compute num_outputs by current fee=0:
    #   total 50_000 > target 10_000 + 0 -> 2 outputs.
    # size = 10 + 148 + 68 = 226.
    assert size == 226
    # fee = 226 * 2000 // 1000 = 452.
    assert fee == 452


def test_compute_fee_and_size_drain_mode_uses_one_output():
    """In drain mode (target=None) there is no cashback output."""
    fee, size = compute_fee_and_size(
        num_inputs=3, total=1_000_000, target=None, fee=0, feekb=1000,
    )
    # 1 output only: 10 + 444 + 34 = 488.
    assert size == 488


# ---------------------------------------------------------------------------
# _loop: live fee/size recomputed on every selection change.
# ---------------------------------------------------------------------------


def test_loop_renders_status_with_live_fee_and_size(monkeypatch):
    """The status line drawn by _loop contains the live fee and size."""
    sources = _sources_with_utxos({0: [100]})
    # fee=0 (compute from feekb), feekb=1000. With default selection
    # of (0,0): 1 input, total=100, target=100 -> total == target, no
    # cashback, 1 output. size = 10 + 148 + 34 = 192. fee = 192.
    screen = MockScreen([ord('\n')])
    _loop(screen, sources, target=100, fee=0, feekb=1000)
    # Last addnstr before the help line is the status (row h-2=22).
    status_draws = [d for d in screen.drawn if d[0] == 22]
    assert status_draws
    line = status_draws[0][2]
    assert 'Target: 0.00000100' in line
    assert 'size=192B' in line


def test_loop_recomputes_fee_when_selection_changes(monkeypatch):
    """Adding an input grows the size, so the live fee grows too."""
    sources = _sources_with_utxos({0: [100, 200]})
    # Start with default selection of (0,0) only (target=100). Cursor
    # is on the address row. Walk down to (0,1), toggle on -> now
    # 2 inputs selected. The next render should show a bigger size.
    screen = MockScreen([curses.KEY_DOWN, curses.KEY_DOWN, ord(' ')])
    # Cancel afterwards so we don't need to also press Enter.
    screen._keys.append(ord('q'))
    _loop(screen, sources, target=100, fee=0, feekb=1000)
    # The second-to-last status draw (just before q cancels) shows
    # 2 inputs / 2 outputs (cashback): 10 + 296 + 68 = 374.
    status_draws = [d for d in screen.drawn if d[0] == 22]
    assert status_draws
    last_status = status_draws[-1][2]
    assert 'size=374B' in last_status


def test_loop_hard_fee_is_not_recomputed():
    """When fee is hard-set, the status line shows it unchanged
    even as the selection grows."""
    sources = _sources_with_utxos({0: [100, 200]})
    screen = MockScreen([curses.KEY_DOWN, curses.KEY_DOWN, ord(' '), ord('\n')])
    _loop(screen, sources, target=100, fee=1234, feekb=1000)
    status_draws = [d for d in screen.drawn if d[0] == 22]
    assert status_draws
    # After the toggle on (0,1): 2 inputs, total=300, target=100,
    # fee=1234 -> 300 > 100+1234 is False, so still 1 output? No wait:
    # 300 > 100 + 1234? No, 300 < 1334. So no cashback. Size = 10 + 296 + 34 = 340.
    last_line = status_draws[-1][2]
    # The fixed fee shows up regardless of selection.
    assert 'fee=0.00001234' in last_line
    # Size still reflects the (now-2-input) selection; no cashback
    # because total 300 < target 100 + fee 1234.
    assert 'size=340B' in last_line


# ---------------------------------------------------------------------------
# run_selection() -- the curses.wrapper entry point. Stub curses.wrapper
# so the test doesn't need a real TTY, but the line is still executed.
# ---------------------------------------------------------------------------


def test_run_selection_calls_curses_wrapper(monkeypatch):
    import yubtc.tui as tui_mod
    sources = _sources_with_utxos({0: [100]})
    captured = {}

    def fake_wrapper(callable_, *args, **kwargs):
        captured['called'] = True
        captured['callable'] = callable_
        captured['args'] = args
        # Pretend we are a terminal: pass through to _loop with a fake screen.
        screen = MockScreen([ord('q')])
        return callable_(screen, *args, **kwargs)
    monkeypatch.setattr(tui_mod.curses, 'wrapper', fake_wrapper)
    addr = b'1ABC'
    assert tui_mod.run_selection(sources, target=100, fee=2000, feekb=3000,
                                 cashback_addr=addr) is None
    assert captured['called'] is True
    assert captured['callable'] is tui_mod._loop
    # (sources, target, fee, feekb, cashback_addr) are forwarded positionally.
    assert captured['args'] == (sources, 100, 2000, 3000, addr)
