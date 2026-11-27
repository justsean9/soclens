"""Comprehensive unit and Textual Pilot tests for Linux-style BSP Tiling (M4)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from textual.widgets import DataTable, Input, OptionList, TabbedContent

from soclens.config import UI_VIEW_ADMIN, UI_VIEW_USER, PivotPayload, get_database_config
from soclens.storage import StorageManager
from soclens.tui import ALL_TABS, USER_VIEW_TABS, SocLensApp, create_app
from soclens.tui.screens.research import ResearchPane
from soclens.tui.tiling import (
    MAX_TILES_PER_WORKSPACE,
    LeafNode,
    PanePickerModal,
    SplitDivider,
    SplitNode,
    TileLeaf,
    TileSplit,
    WorkspaceHost,
    WorkspaceLayoutState,
    adjust_split_ratio,
    clamp_ratio,
    compute_rects,
    count_leaves,
    find_adjacent_non_source,
    find_neighbor,
    leaf_pane_ids,
    node_from_dict,
    node_to_dict,
    remove_leaf,
    replace_leaf,
    split_leaf,
    swap_leaves,
)


def _make_rf_client() -> MagicMock:
    client = MagicMock()
    client.api_token = ""
    client.sandbox_token = ""
    client.verify_ssl = True
    return client


# ---------------------------------------------------------------------------
# 1. Pure BSP Tree & Serialization Unit Tests
# ---------------------------------------------------------------------------


def test_bsp_tree_serialization_and_ratio_clamping() -> None:
    tree = SplitNode(
        direction="horizontal",
        ratio=0.625,
        first=LeafNode("tab-research", leaf_id="leaf-1"),
        second=SplitNode(
            direction="vertical",
            ratio=0.95,  # clamped to 0.9
            first=LeafNode("tab-rf-intel", leaf_id="leaf-2"),
            second=LeafNode("tab-logs", leaf_id="leaf-3"),
        ),
    )
    assert tree.second.ratio == pytest.approx(0.9)
    assert clamp_ratio(-5.0) == pytest.approx(0.1)
    assert clamp_ratio(5.0) == pytest.approx(0.9)
    assert clamp_ratio("not-a-float") == pytest.approx(0.5)

    raw = node_to_dict(tree)
    restored = node_from_dict(raw, valid_pane_ids=ALL_TABS, fallback_pane_id="tab-research")
    assert isinstance(restored, SplitNode)
    assert leaf_pane_ids(restored) == ["tab-research", "tab-rf-intel", "tab-logs"]
    assert restored.ratio == pytest.approx(0.625)
    assert isinstance(restored.second, SplitNode)
    assert restored.second.ratio == pytest.approx(0.9)


def test_bsp_tree_sanitization_drops_corrupt_duplicates_and_excess_leaves() -> None:
    corrupt_payload = {
        "type": "split",
        "direction": "diagonal",
        "ratio": 0.01,
        "first": {
            "type": "split",
            "direction": "vertical",
            "ratio": 0.5,
            "first": {"type": "leaf", "pane_id": "tab-research"},
            "second": {"type": "leaf", "pane_id": "tab-nonexistent"},
        },
        "second": {
            "type": "split",
            "direction": "horizontal",
            "ratio": 0.5,
            "first": {"type": "leaf", "pane_id": "tab-research"},  # duplicate
            "second": {
                "type": "split",
                "direction": "vertical",
                "ratio": 0.5,
                "first": {"type": "leaf", "pane_id": "tab-logs"},
                "second": {
                    "type": "split",
                    "direction": "horizontal",
                    "ratio": 0.5,
                    "first": {"type": "leaf", "pane_id": "tab-sentinelone"},
                    "second": {
                        "type": "split",
                        "direction": "vertical",
                        "ratio": 0.5,
                        "first": {"type": "leaf", "pane_id": "tab-llm"},
                        "second": {"type": "leaf", "pane_id": "tab-settings"},
                    },
                },
            },
        },
    }
    sanitized = node_from_dict(
        corrupt_payload,
        valid_pane_ids=USER_VIEW_TABS,
        fallback_pane_id="tab-research",
    )
    leaves = leaf_pane_ids(sanitized)
    assert len(leaves) == MAX_TILES_PER_WORKSPACE
    assert len(set(leaves)) == len(leaves)
    assert "tab-nonexistent" not in leaves
    assert leaves == ["tab-research", "tab-logs", "tab-sentinelone", "tab-llm"]

    only_bad = node_from_dict(
        {"type": "leaf", "pane_id": "tab-unknown"},
        valid_pane_ids=USER_VIEW_TABS,
        fallback_pane_id="tab-rf-intel",
    )
    assert isinstance(only_bad, LeafNode)
    assert only_bad.pane_id == "tab-rf-intel"

    # Full layout state sanitization
    layout = WorkspaceLayoutState.from_dict(
        {
            "mode": "bogus_mode",
            "active_workspace": 99,
            "active_pane_id": "tab-dashboard",  # blocked in user view
            "workspaces": {
                "1": {"tree": {"type": "leaf", "pane_id": "tab-dashboard"}},
                "9": {"tree": {"type": "leaf", "pane_id": "tab-logs"}},
            },
        },
        valid_pane_ids=USER_VIEW_TABS,
        fallback_pane_id="tab-research",
    )
    assert layout.mode == "tabbed"
    assert layout.active_workspace == 1
    assert layout.active_pane_id == "tab-research"
    assert 9 not in layout.workspaces
    assert leaf_pane_ids(layout.workspaces[1].tree) == ["tab-research"]


def test_bsp_pure_operations_geometry_and_neighbors() -> None:
    tree: LeafNode | SplitNode = LeafNode("tab-research")
    tree, ok = split_leaf(tree, "tab-research", "tab-rf-intel", "horizontal")
    assert ok is True
    tree, ok = split_leaf(tree, "tab-rf-intel", "tab-logs", "vertical")
    assert ok is True
    tree, ok = split_leaf(tree, "tab-research", "tab-llm", "vertical")
    assert ok is True
    assert count_leaves(tree) == 4
    # 5th split refused at 4-tile cap
    tree, ok = split_leaf(tree, "tab-llm", "tab-settings", "horizontal")
    assert ok is False

    rects = compute_rects(tree)
    assert set(rects) == {"tab-research", "tab-llm", "tab-rf-intel", "tab-logs"}
    assert find_neighbor(tree, "tab-research", 1, 0) == "tab-rf-intel"
    assert find_neighbor(tree, "tab-research", 0, 1) == "tab-llm"
    assert find_neighbor(tree, "tab-logs", -1, 0) == "tab-llm"
    assert find_neighbor(tree, "tab-logs", 0, -1) == "tab-rf-intel"
    assert find_adjacent_non_source(tree, "tab-research") == "tab-llm"

    swapped, ok = swap_leaves(tree, "tab-research", "tab-rf-intel")
    assert ok is True
    assert find_neighbor(swapped, "tab-rf-intel", 1, 0) == "tab-research"

    replaced, ok = replace_leaf(swapped, "tab-logs", "tab-settings")
    assert ok is True
    assert "tab-settings" in leaf_pane_ids(replaced)
    assert "tab-logs" not in leaf_pane_ids(replaced)

    resized, ok = adjust_split_ratio(replaced, "tab-rf-intel", 1, 0, step=0.1)
    assert ok is True
    assert isinstance(resized, SplitNode)
    assert resized.ratio == pytest.approx(0.6)

    pruned, ok = remove_leaf(replaced, "tab-settings")
    assert ok is True
    assert pruned is not None
    assert count_leaves(pruned) == 3


# ---------------------------------------------------------------------------
# 2. Default Mode, Persistence & Profile/Workstation Scoping
# ---------------------------------------------------------------------------


def test_fresh_install_defaults_tabbed_and_persists_tiling_across_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOCLENS_WORKSTATION_ID", "ws-tiling-1")
    monkeypatch.setenv("SOCLENS_PROFILE", "analyst-alpha")

    app1 = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run_first() -> None:
        async with app1.run_test(size=(130, 38)) as pilot:
            await pilot.pause()
            host = app1.query_one(WorkspaceHost)
            assert host.mode == "tabbed"
            assert app1.query_one("#main-tabs", TabbedContent).display is True
            assert app1.query_one("#tiling-root").display is False

            await pilot.press("alt+t")
            await pilot.pause()
            assert host.mode == "tiling"
            assert app1.query_one("#main-tabs", TabbedContent).display is False
            assert app1.query_one("#tiling-root").display is True
            assert len(app1.query(TileLeaf)) == 1

            await pilot.press("alt+v")
            await pilot.pause()
            assert len(app1.query(TileLeaf)) == 2
            assert len(app1.query(TileSplit)) == 1
            assert len(app1.query(SplitDivider)) == 1

    asyncio.run(_run_first())

    # Restart on same workspace & workstation/profile -> restores tiling + 2 tiles
    app2 = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run_second() -> None:
        async with app2.run_test(size=(130, 38)) as pilot:
            await pilot.pause()
            host = app2.query_one(WorkspaceHost)
            assert host.mode == "tiling"
            assert len(app2.query(TileLeaf)) == 2

    asyncio.run(_run_second())

    # Different profile on same workspace remains isolated (fresh tabbed mode)
    monkeypatch.setenv("SOCLENS_PROFILE", "analyst-beta")
    app3 = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run_third() -> None:
        async with app3.run_test(size=(130, 38)) as pilot:
            await pilot.pause()
            assert app3.query_one(WorkspaceHost).mode == "tabbed"

    asyncio.run(_run_third())


def test_corrupt_persisted_layout_recovers_gracefully(tmp_path: Path) -> None:
    storage = StorageManager(get_database_config(workspace_dir=tmp_path))
    storage.ensure_schema()
    storage.save_workspace_layout(
        mode="tiling",
        state={
            "active_workspace": 99,
            "active_pane_id": "tab-nonexistent",
            "workspaces": {
                "1": {
                    "tree": {"type": "leaf", "pane_id": "tab-nonexistent"},
                    "focused_pane_id": "tab-nonexistent",
                }
            },
        },
    )
    storage.dispose()

    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            host = app.query_one(WorkspaceHost)
            assert host.mode == "tiling"
            assert host.active_workspace == 1
            assert host.active_pane_id == "tab-research"
            assert len(app.query(TileLeaf)) == 1

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. Single-Instance Enforcement, Admin Gating & State Preservation
# ---------------------------------------------------------------------------


def test_single_instance_across_all_13_panes_and_admin_gating(tmp_path: Path) -> None:
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        view_mode=UI_VIEW_ADMIN,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            host = app.query_one(WorkspaceHost)
            await pilot.press("alt+t")
            await pilot.pause()

            # Split into 2 tiles and verify activating an already-visible pane focuses without duplicating
            await pilot.press("alt+v")
            await pilot.pause()
            leaves = list(app.query(TileLeaf))
            assert len(leaves) == 2
            left_pane_id = leaves[0].pane_id
            right_pane_id = leaves[1].pane_id
            assert host.active_pane_id == right_pane_id

            assert host.switch_to_pane(left_pane_id) is True
            await pilot.pause()
            assert host.active_pane_id == left_pane_id
            assert len(app.query(TileLeaf)) == 2

            # Cycle through all 13 panes without DuplicateIds and <= 1 instance per pane class
            for tid in ALL_TABS:
                assert host.switch_to_pane(tid) is True
                await pilot.pause()
                assert len(app.query(SocLensApp._TAB_PANE_CLASSES[tid])) == 1

            for tid in ALL_TABS:
                assert len(app.query(SocLensApp._TAB_PANE_CLASSES[tid])) <= 1

            # Put an admin pane in focused tile, then toggle F2 to User view -> evicts admin tile
            assert host.switch_to_pane("tab-sigma") is True
            await pilot.pause()
            assert host.active_pane_id == "tab-sigma"

            await pilot.press("f2")
            await pilot.pause()
            assert app.view_mode == UI_VIEW_USER
            visible_ids = [lf.pane_id for lf in app.query(TileLeaf)]
            assert "tab-sigma" not in visible_ids
            assert host.switch_to_pane("tab-dashboard") is False

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Keybindings: Splits, Picker, Focus, Swap, Resize, Drag, Zoom, Close, WS
# ---------------------------------------------------------------------------


def test_tiling_keybindings_picker_focus_swap_resize_drag_zoom_close_workspaces(
    tmp_path: Path,
) -> None:
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            host = app.query_one(WorkspaceHost)

            # Tiling-only shortcuts are inactive in Tabbed Mode
            await pilot.press("alt+v")
            await pilot.pause()
            assert host.mode == "tabbed"
            assert len(app.query(TileLeaf)) == 0

            # Enter Tiling Mode (Alt+t)
            await pilot.press("alt+t")
            await pilot.pause()
            assert host.mode == "tiling"
            assert len(app.query(TileLeaf)) == 1

            # Alt+q on last remaining tile refuses to close
            await pilot.press("alt+q")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 1

            # Preserve input state on ResearchPane across splits, swaps, and mode toggle
            res_input = app.query_one("#res-target-input", Input)
            res_input.value = "evil-domain.example"

            # Alt+v splits right (horizontal), Alt+s splits down (vertical)
            await pilot.press("alt+v")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 2
            assert len(app.query(TileSplit)) == 1
            split_h = app.query_one(TileSplit)
            assert split_h.direction == "horizontal"

            # Alt+p opens PanePickerModal, Escape dismisses, Enter selects
            stack_before = len(app.screen_stack)
            await pilot.press("alt+p")
            await pilot.pause()
            assert len(app.screen_stack) > stack_before
            assert isinstance(app.screen, PanePickerModal)
            await pilot.press("escape")
            await pilot.pause()
            assert len(app.screen_stack) == stack_before

            await pilot.press("alt+p")
            await pilot.pause()
            opts = app.screen.query_one("#pane-picker-options", OptionList)
            opts.highlighted = opts.get_option_index("tab-logs")
            await pilot.press("enter")
            await pilot.pause()
            assert host.active_pane_id == "tab-logs"

            # Directional focus: Alt+h / Alt+Left moves to left tile, Alt+l / Alt+Right moves right
            await pilot.press("alt+h")
            await pilot.pause()
            assert host.active_pane_id == "tab-research"
            await pilot.press("alt+right")
            await pilot.pause()
            assert host.active_pane_id == "tab-logs"
            await pilot.press("alt+left")
            await pilot.pause()
            assert host.active_pane_id == "tab-research"

            # Swap tiles: Alt+Shift+l moves left tile to the right while keeping Input state
            leaves_before = {lf.pane_id: lf.region for lf in app.query(TileLeaf)}
            assert leaves_before["tab-research"].x < leaves_before["tab-logs"].x

            await pilot.press("alt+shift+l")
            await pilot.pause()
            leaves_after = {lf.pane_id: lf.region for lf in app.query(TileLeaf)}
            assert leaves_after["tab-research"].x > leaves_after["tab-logs"].x
            assert app.query_one("#res-target-input", Input).value == "evil-domain.example"
            assert len(app.query(ResearchPane)) == 1

            # Resize via Alt+Ctrl+Left / Right (clamped [0.1, 0.9])
            ratio_before = app.query_one(TileSplit).ratio
            await pilot.press("alt+ctrl+right")
            await pilot.pause()
            assert app.query_one(TileSplit).ratio > ratio_before
            for _ in range(12):
                await pilot.press("alt+ctrl+left")
            await pilot.pause()
            assert app.query_one(TileSplit).ratio >= 0.1

            # Mouse drag SplitDivider back to ~70% width
            divider = app.query_one(SplitDivider)
            parent_split = app.query_one(TileSplit)
            drag_offset = (
                int(parent_split.region.width * 0.72),
                max(1, divider.region.y - parent_split.region.y + 1),
            )
            await pilot.mouse_down(divider)
            await pilot.hover(parent_split, offset=drag_offset)
            await pilot.mouse_up(parent_split, offset=drag_offset)
            await pilot.pause()
            assert app.query_one(TileSplit).ratio > 0.55

            # Split down (Alt+s) and test vertical focus Alt+k / Alt+j + nested vertical resize
            await pilot.press("alt+s")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 3
            down_pane = host.active_pane_id
            await pilot.press("alt+k")
            await pilot.pause()
            assert host.active_pane_id != down_pane
            await pilot.press("alt+j")
            await pilot.pause()
            assert host.active_pane_id == down_pane
            v_splits = [s for s in app.query(TileSplit) if s.direction == "vertical"]
            assert v_splits
            v_before = v_splits[-1].ratio
            await pilot.press("alt+ctrl+down")
            await pilot.pause()
            assert v_splits[-1].ratio > v_before

            # Max 4 tiles cap on manual splits
            await pilot.press("alt+v")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 4
            await pilot.press("alt+v")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 4

            # Zoom toggle (Alt+z)
            focused_before_zoom = host.active_pane_id
            await pilot.press("alt+z")
            await pilot.pause()
            assert host.zoomed is True
            visible_leaves = [lf for lf in app.query(TileLeaf) if lf.display]
            assert len(visible_leaves) == 1
            assert visible_leaves[0].pane_id == focused_before_zoom
            assert "[ZOOM]" in str(visible_leaves[0].border_title)

            await pilot.press("alt+z")
            await pilot.pause()
            assert host.zoomed is False
            assert len([lf for lf in app.query(TileLeaf) if lf.display]) == 4

            # Close tile (Alt+q) reduces count 4 -> 3
            await pilot.press("alt+q")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 3

            # Named workspaces Alt+1..5 keep independent layouts + invalid slot raises ValueError
            await pilot.press("alt+2")
            await pilot.pause()
            assert host.active_workspace == 2
            assert len(app.query(TileLeaf)) == 1
            await pilot.press("alt+v")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 2

            await pilot.press("alt+1")
            await pilot.pause()
            assert host.active_workspace == 1
            assert len(app.query(TileLeaf)) == 3

            with pytest.raises(ValueError):
                host.switch_workspace(6)
            with pytest.raises(ValueError):
                host.switch_workspace(0)
            assert host.active_workspace == 1

            # Toggle back to Tabbed Mode preserves ResearchPane Input state
            await pilot.press("alt+t")
            await pilot.pause()
            assert host.mode == "tabbed"
            assert app.query_one("#res-target-input", Input).value == "evil-domain.example"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Per-Tile Compact CSS Rules & Responsive Resize
# ---------------------------------------------------------------------------


def test_tile_leaf_compact_css_classes_and_app_css_rules(tmp_path: Path) -> None:
    assert ".-compact-narrow" in SocLensApp.CSS
    assert ".tile-leaf.tile-compact" in SocLensApp.CSS
    assert ".tile-leaf.tile-short" in SocLensApp.CSS

    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            await pilot.press("alt+t")
            await pilot.press("alt+v")
            await pilot.pause()

            leaves = list(app.query(TileLeaf))
            assert len(leaves) == 2
            # Each tile width ~49 (< 96) -> compact classes applied per tile
            for leaf in leaves:
                assert leaf.has_class("-compact-narrow")
                assert leaf.has_class("tile-compact")

            # Very small terminal -> tile-short also applied
            await pilot.resize_terminal(48, 16)
            await pilot.pause()
            for leaf in app.query(TileLeaf):
                assert leaf.has_class("-compact-narrow")
                assert leaf.has_class("tile-compact")
                assert leaf.has_class("tile-short")

            # Wide terminal -> compact classes cleared
            await pilot.resize_terminal(220, 60)
            await pilot.pause()
            for leaf in app.query(TileLeaf):
                assert not leaf.has_class("-compact-narrow")
                assert not leaf.has_class("tile-compact")
                assert not leaf.has_class("tile-short")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 6. Cross-Tile dispatch_pivot() 4-Tile Cap & Tabbed Mode Compatibility
# ---------------------------------------------------------------------------


def test_dispatch_pivot_tiling_in_place_auto_split_and_4_tile_cap(tmp_path: Path) -> None:
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(150, 44)) as pilot:
            await pilot.pause()
            host = app.query_one(WorkspaceHost)

            # Tabbed Mode pivot still switches #main-tabs directly
            assert app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-research",
                    target_tab="tab-rf-intel",
                    entity="198.51.100.10",
                    entity_type="ip",
                )
            )
            await pilot.pause()
            assert host.mode == "tabbed"
            assert app.query_one("#main-tabs", TabbedContent).active == "tab-rf-intel"
            assert app.query_one("#rf-ioc-input", Input).value == "198.51.100.10"

            # Enter Tiling Mode (1 tile: tab-rf-intel)
            await pilot.press("alt+t")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 1

            # Invalid & admin-blocked pivots fail cleanly
            assert app.dispatch_pivot(PivotPayload(target_tab="tab-nonexistent")) is False
            assert app.dispatch_pivot(PivotPayload(target_tab="tab-sigma")) is False

            # Pivot from tab-rf-intel -> tab-research auto-splits to 2 tiles
            assert app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-rf-intel",
                    target_tab="tab-research",
                    entity="evil.example",
                    entity_type="domain",
                )
            )
            await pilot.pause()
            visible = {lf.pane_id for lf in app.query(TileLeaf)}
            assert visible == {"tab-rf-intel", "tab-research"}
            assert app.query_one("#res-target-input", Input).value == "evil.example"

            # Pivot to already-visible target updates in place (stays at 2 tiles)
            assert app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-research",
                    target_tab="tab-rf-intel",
                    entity="203.0.113.7",
                    entity_type="ip",
                )
            )
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 2
            assert app.query_one("#rf-ioc-input", Input).value == "203.0.113.7"

            # Pivot to 3rd and 4th panes fills workspace up to 4-tile cap
            assert app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-rf-intel",
                    target_tab="tab-splunk-search",
                    src_ip="203.0.113.7",
                )
            )
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 3

            assert app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-rf-intel",
                    target_tab="tab-sentinelone",
                    hostname="HOST-01",
                )
            )
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 4
            assert app.query_one("#s1-filter-input", Input).value == "HOST-01"

            # Pivot to 5th pane from tab-rf-intel reuses adjacent non-source tile (stays <= 4, source stays visible)
            assert app.dispatch_pivot(
                PivotPayload(
                    source_tab="tab-rf-intel",
                    target_tab="tab-llm",
                    summary="Investigate 203.0.113.7",
                )
            )
            await pilot.pause()
            final_visible = {lf.pane_id for lf in app.query(TileLeaf)}
            assert len(final_visible) == 4
            assert "tab-rf-intel" in final_visible
            assert "tab-llm" in final_visible
            assert len(app.query(DataTable)) >= 1

    asyncio.run(_run())


def test_dashboard_pane_split_uses_tile_width_and_switch_to_pane(tmp_path: Path) -> None:
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        view_mode=UI_VIEW_ADMIN,
        initial_tab="tab-dashboard",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.press("alt+t")
            await pilot.pause()
            dash_ws = app.query_one("#dash-workspace")
            assert dash_ws.has_class("split-horizontal")

            # Split horizontally -> each tile width ~69 (< 110), so DashboardPane drops split-horizontal
            await pilot.press("alt+v")
            await pilot.pause()
            assert not dash_ws.has_class("split-horizontal")

            # BaseSocPane.switch_to_pane routes cleanly without touching #main-tabs directly
            from soclens.tui.screens.dashboard import DashboardPane

            dash_pane = app.query_one(DashboardPane)
            assert dash_pane.switch_to_pane("tab-settings") is True
            await pilot.pause()
            assert app.query_one(WorkspaceHost).active_pane_id == "tab-settings"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 7. Real-Compositor Wide-to-Narrow Reflow, Profile Reload & Focus Restore
# ---------------------------------------------------------------------------


def _restore_real_compositor(monkeypatch: pytest.MonkeyPatch) -> None:
    import textual.screen

    cur = textual.screen.Screen._compositor_refresh
    if cur.__name__ != "_compositor_refresh":
        for cell in cur.__closure__ or ():
            val = cell.cell_contents
            if callable(val) and getattr(val, "__name__", "") == "_compositor_refresh":
                monkeypatch.setattr(textual.screen.Screen, "_compositor_refresh", val)
                break


def test_real_compositor_wide_to_narrow_drag_and_4tile_shrink_no_chop_cells_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _restore_real_compositor(monkeypatch)

    async def _run_drag_case(case_dir: Path, initial_tab: str) -> None:
        case_dir.mkdir(parents=True, exist_ok=True)
        app = create_app(
            client=_make_rf_client(),
            dry_run=True,
            initial_tab=initial_tab,
            workspace_dir=case_dir,
            no_secret_store=True,
        )
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            await pilot.press("alt+t")
            await pilot.pause()
            await pilot.press("alt+v")
            await pilot.pause()

            divider = app.query_one(SplitDivider)
            parent_split = app.query_one(TileSplit)
            await pilot.mouse_down(divider)
            await pilot.hover(parent_split, offset=(0, 5))
            await pilot.mouse_up(parent_split, offset=(0, 5))
            await pilot.pause()
            assert app._exception is None

            divider = app.query_one(SplitDivider)
            parent_split = app.query_one(TileSplit)
            await pilot.mouse_down(divider)
            await pilot.hover(parent_split, offset=(159, 5))
            await pilot.mouse_up(parent_split, offset=(159, 5))
            await pilot.pause()
            assert app._exception is None

            app.screen._compositor.render_update(screen_stack=app._background_screens)
            assert app._exception is None

    async def _run_es_4tile(case_dir: Path) -> None:
        case_dir.mkdir(parents=True, exist_ok=True)
        app = create_app(
            client=_make_rf_client(),
            dry_run=True,
            initial_tab="tab-splunk-es",
            workspace_dir=case_dir,
            no_secret_store=True,
        )
        async with app.run_test(size=(150, 44)) as pilot:
            await pilot.pause()
            await pilot.press("alt+t")
            await pilot.pause()
            await pilot.press("alt+v")
            await pilot.pause()
            await pilot.press("alt+h")
            await pilot.pause()
            await pilot.press("alt+s")
            await pilot.pause()
            await pilot.press("alt+l")
            await pilot.pause()
            await pilot.press("alt+s")
            await pilot.pause()
            for _ in range(9):
                await pilot.press("alt+ctrl+left")
            await pilot.pause()
            assert len(app.query(TileLeaf)) == 4
            assert app._exception is None
            app.screen._compositor.render_update(screen_stack=app._background_screens)
            assert app._exception is None

    async def _run_all() -> None:
        # RFIntelPane starts on the right side when initial_tab="tab-research"
        await _run_drag_case(tmp_path / "rf_drag", "tab-research")
        await _run_drag_case(tmp_path / "es_drag", "tab-splunk-es")
        await _run_drag_case(tmp_path / "logs_drag", "tab-logs")
        await _run_es_4tile(tmp_path / "es_4tile")

    asyncio.run(_run_all())


def test_reload_settings_reloads_workspace_host_for_switched_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCLENS_PROFILE", "prof-b")
    storage_b = StorageManager(get_database_config(workspace_dir=tmp_path))
    storage_b.ensure_schema()
    storage_b.save_workspace_layout(
        mode="tabbed",
        state={
            "mode": "tabbed",
            "active_workspace": 1,
            "active_pane_id": "tab-logs",
            "workspaces": {},
        },
    )
    storage_b.dispose()

    monkeypatch.setenv("SOCLENS_PROFILE", "prof-a")
    app = create_app(
        client=_make_rf_client(),
        dry_run=True,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            host = app.query_one(WorkspaceHost)
            assert host.mode == "tabbed"

            await pilot.press("alt+t")
            await pilot.pause()
            await pilot.press("alt+v")
            await pilot.pause()
            assert host.mode == "tiling"
            assert len(app.query(TileLeaf)) == 2

            # Switch to prof-b via reload_settings -> switches to tabbed without clobbering prof-b
            monkeypatch.setenv("SOCLENS_PROFILE", "prof-b")
            app.reload_settings()
            await pilot.pause()
            assert app.storage.config.profile_name == "prof-b"
            assert host.mode == "tabbed"
            assert app.query_one("#main-tabs", TabbedContent).display is True
            assert app.query_one("#tiling-root").display is False

            saved_b = app.storage.load_workspace_layout(profile_name="prof-b")
            assert saved_b["mode"] == "tabbed"

            # Switch back to prof-a -> restores prof-a tiling layout
            monkeypatch.setenv("SOCLENS_PROFILE", "prof-a")
            app.reload_settings()
            await pilot.pause()
            assert app.storage.config.profile_name == "prof-a"
            assert host.mode == "tiling"
            assert len(app.query(TileLeaf)) == 2

    asyncio.run(_run())


def test_restart_preserves_persisted_focused_pane_even_when_initial_tab_in_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCLENS_WORKSTATION_ID", "ws-focus-1")
    monkeypatch.setenv("SOCLENS_PROFILE", "focus-profile")

    app1 = create_app(
        client=_make_rf_client(),
        dry_run=True,
        view_mode=UI_VIEW_ADMIN,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run_first() -> None:
        async with app1.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            host = app1.query_one(WorkspaceHost)
            await pilot.press("alt+t")
            await pilot.pause()
            await pilot.press("alt+v")
            await pilot.pause()
            assert host.switch_to_pane("tab-watchlists") is True
            await pilot.pause()
            assert host.active_pane_id == "tab-watchlists"

    asyncio.run(_run_first())

    app2 = create_app(
        client=_make_rf_client(),
        dry_run=True,
        view_mode=UI_VIEW_ADMIN,
        initial_tab="tab-research",
        workspace_dir=tmp_path,
        no_secret_store=True,
    )

    async def _run_second() -> None:
        async with app2.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            host2 = app2.query_one(WorkspaceHost)
            assert host2.mode == "tiling"
            assert host2.active_pane_id == "tab-watchlists"

    asyncio.run(_run_second())
