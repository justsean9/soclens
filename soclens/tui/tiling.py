"""Linux-style Binary Space Partitioning (BSP) tiling window manager for SOCLens TUI."""

from __future__ import annotations

import contextlib
import math
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Literal, cast

from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.content import Content
from textual.message import Message
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import OptionList, Static, TabbedContent, TabPane
from textual.widgets.option_list import Option

if TYPE_CHECKING:
    from soclens.tui.screens.base import BaseSocPane

MAX_TILES_PER_WORKSPACE: int = 4
MIN_SPLIT_RATIO: float = 0.1
MAX_SPLIT_RATIO: float = 0.9
DEFAULT_SPLIT_RATIO: float = 0.5
WORKSPACE_SLOTS: tuple[int, ...] = (1, 2, 3, 4, 5)

SplitDirection = Literal["horizontal", "vertical"]
WorkspaceMode = Literal["tabbed", "tiling"]


def clamp_ratio(value: Any, default: float = DEFAULT_SPLIT_RATIO) -> float:
    """Clamp split ratio to ``[MIN_SPLIT_RATIO, MAX_SPLIT_RATIO]``."""
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(numeric) or math.isinf(numeric):
        return default
    clamped = max(MIN_SPLIT_RATIO, min(MAX_SPLIT_RATIO, numeric))
    return round(clamped, 4)


def _normalize_direction(value: Any) -> SplitDirection:
    return "vertical" if str(value or "").strip().lower() == "vertical" else "horizontal"


@dataclass
class LeafNode:
    """Single tile leaf holding one ``BaseSocPane`` identified by ``pane_id``."""

    pane_id: str
    leaf_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "leaf",
            "pane_id": self.pane_id,
            "leaf_id": self.leaf_id,
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        valid_pane_ids: Sequence[str] | set[str],
        fallback_pane_id: str,
    ) -> LeafNode:
        valid_set = set(valid_pane_ids)
        raw_pane = str(data.get("pane_id") or "").strip() if isinstance(data, Mapping) else ""
        if raw_pane in valid_set:
            pane_id = raw_pane
        elif fallback_pane_id in valid_set:
            pane_id = fallback_pane_id
        else:
            pane_id = next(iter(valid_pane_ids), "tab-research")
        raw_leaf = str(data.get("leaf_id") or "").strip() if isinstance(data, Mapping) else ""
        return cls(pane_id=pane_id, leaf_id=raw_leaf or uuid.uuid4().hex[:8])

    def iter_leaves(self) -> Iterator[LeafNode]:
        yield self

    def count_leaves(self) -> int:
        return 1


@dataclass
class SplitNode:
    """Binary BSP split node dividing space between ``first`` and ``second``."""

    direction: SplitDirection
    first: BSPNode
    second: BSPNode
    ratio: float = DEFAULT_SPLIT_RATIO

    def __post_init__(self) -> None:
        self.direction = _normalize_direction(self.direction)
        self.ratio = clamp_ratio(self.ratio)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "split",
            "direction": self.direction,
            "ratio": self.ratio,
            "first": self.first.to_dict(),
            "second": self.second.to_dict(),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        valid_pane_ids: Sequence[str] | set[str],
        fallback_pane_id: str,
        *,
        max_leaves: int = MAX_TILES_PER_WORKSPACE,
    ) -> BSPNode:
        return node_from_dict(
            data,
            valid_pane_ids=valid_pane_ids,
            fallback_pane_id=fallback_pane_id,
            max_leaves=max_leaves,
        )

    def iter_leaves(self) -> Iterator[LeafNode]:
        yield from self.first.iter_leaves()
        yield from self.second.iter_leaves()

    def count_leaves(self) -> int:
        return self.first.count_leaves() + self.second.count_leaves()


BSPNode = LeafNode | SplitNode


def node_to_dict(node: BSPNode) -> dict[str, Any]:
    """Serialize a ``LeafNode`` or ``SplitNode`` tree to JSON-safe dict."""
    return node.to_dict()


def node_from_dict(
    data: Any,
    valid_pane_ids: Sequence[str] | set[str],
    fallback_pane_id: str,
    *,
    max_leaves: int = MAX_TILES_PER_WORKSPACE,
) -> BSPNode:
    """Deserialize and sanitize a BSP tree, filtering unknown/duplicate panes and >cap leaves."""
    valid_list = list(valid_pane_ids)
    valid_set = set(valid_list)
    effective_fallback = (
        fallback_pane_id
        if fallback_pane_id in valid_set
        else (valid_list[0] if valid_list else "tab-research")
    )
    cap = max(1, int(max_leaves))
    seen_panes: set[str] = set()

    def _parse(raw: Any, depth: int = 0) -> BSPNode | None:
        if depth > 32 or not isinstance(raw, Mapping):
            return None
        node_type = str(raw.get("type") or "").strip().lower()
        is_split = node_type == "split" or ("first" in raw and "second" in raw)
        if is_split:
            first_node = _parse(raw.get("first"), depth + 1)
            second_node = _parse(raw.get("second"), depth + 1)
            if first_node is not None and second_node is not None:
                return SplitNode(
                    direction=_normalize_direction(raw.get("direction")),
                    first=first_node,
                    second=second_node,
                    ratio=clamp_ratio(raw.get("ratio", DEFAULT_SPLIT_RATIO)),
                )
            return first_node if first_node is not None else second_node

        pane_id = str(raw.get("pane_id") or "").strip()
        if pane_id not in valid_set or pane_id in seen_panes or len(seen_panes) >= cap:
            return None
        seen_panes.add(pane_id)
        leaf_id = str(raw.get("leaf_id") or "").strip() or uuid.uuid4().hex[:8]
        return LeafNode(pane_id=pane_id, leaf_id=leaf_id)

    parsed = _parse(data)
    if parsed is None:
        return LeafNode(pane_id=effective_fallback)
    return parsed


def iter_leaves(node: BSPNode) -> Iterator[LeafNode]:
    """Yield all ``LeafNode`` leaves in left-to-right / top-to-bottom order."""
    yield from node.iter_leaves()


def count_leaves(node: BSPNode) -> int:
    """Count total leaves in ``node``."""
    return node.count_leaves()


def leaf_pane_ids(node: BSPNode) -> list[str]:
    """Return ordered list of ``pane_id``s present in ``node``."""
    return [leaf.pane_id for leaf in node.iter_leaves()]


def contains_pane(node: BSPNode, pane_id: str) -> bool:
    """Return True if ``pane_id`` is present in ``node``."""
    return any(leaf.pane_id == pane_id for leaf in node.iter_leaves())


def split_leaf(
    node: BSPNode,
    target_pane_id: str,
    new_pane_id: str,
    direction: SplitDirection,
    ratio: float = DEFAULT_SPLIT_RATIO,
    *,
    max_leaves: int = MAX_TILES_PER_WORKSPACE,
) -> tuple[BSPNode, bool]:
    """Split ``target_pane_id`` into ``SplitNode(direction, target, new)``."""
    if (
        not target_pane_id
        or not new_pane_id
        or target_pane_id == new_pane_id
        or contains_pane(node, new_pane_id)
        or count_leaves(node) >= max_leaves
    ):
        return node, False

    clean_dir = _normalize_direction(direction)
    clean_ratio = clamp_ratio(ratio)

    def _walk(cur: BSPNode) -> tuple[BSPNode, bool]:
        if isinstance(cur, LeafNode):
            if cur.pane_id == target_pane_id:
                return (
                    SplitNode(
                        direction=clean_dir,
                        first=LeafNode(pane_id=cur.pane_id, leaf_id=cur.leaf_id),
                        second=LeafNode(pane_id=new_pane_id),
                        ratio=clean_ratio,
                    ),
                    True,
                )
            return cur, False
        new_first, changed = _walk(cur.first)
        if changed:
            return (
                SplitNode(
                    direction=cur.direction,
                    first=new_first,
                    second=cur.second,
                    ratio=cur.ratio,
                ),
                True,
            )
        new_second, changed = _walk(cur.second)
        if changed:
            return (
                SplitNode(
                    direction=cur.direction,
                    first=cur.first,
                    second=new_second,
                    ratio=cur.ratio,
                ),
                True,
            )
        return cur, False

    return _walk(node)


def replace_leaf(
    node: BSPNode,
    target_pane_id: str,
    new_pane_id: str,
) -> tuple[BSPNode, bool]:
    """Replace ``target_pane_id`` leaf with ``new_pane_id`` without changing layout."""
    if not target_pane_id or not new_pane_id:
        return node, False
    if target_pane_id == new_pane_id:
        return node, contains_pane(node, target_pane_id)
    if contains_pane(node, new_pane_id):
        return node, False

    def _walk(cur: BSPNode) -> tuple[BSPNode, bool]:
        if isinstance(cur, LeafNode):
            if cur.pane_id == target_pane_id:
                return LeafNode(pane_id=new_pane_id, leaf_id=cur.leaf_id), True
            return cur, False
        new_first, changed = _walk(cur.first)
        if changed:
            return (
                SplitNode(
                    direction=cur.direction,
                    first=new_first,
                    second=cur.second,
                    ratio=cur.ratio,
                ),
                True,
            )
        new_second, changed = _walk(cur.second)
        if changed:
            return (
                SplitNode(
                    direction=cur.direction,
                    first=cur.first,
                    second=new_second,
                    ratio=cur.ratio,
                ),
                True,
            )
        return cur, False

    return _walk(node)


def remove_leaf(node: BSPNode, target_pane_id: str) -> tuple[BSPNode | None, bool]:
    """Remove ``target_pane_id`` from ``node``, promoting its sibling split branch."""
    if isinstance(node, LeafNode):
        if node.pane_id == target_pane_id:
            return None, True
        return node, False

    new_first, removed = remove_leaf(node.first, target_pane_id)
    if removed:
        if new_first is None:
            return node.second, True
        return (
            SplitNode(
                direction=node.direction,
                first=new_first,
                second=node.second,
                ratio=node.ratio,
            ),
            True,
        )

    new_second, removed = remove_leaf(node.second, target_pane_id)
    if removed:
        if new_second is None:
            return node.first, True
        return (
            SplitNode(
                direction=node.direction,
                first=node.first,
                second=new_second,
                ratio=node.ratio,
            ),
            True,
        )
    return node, False


def swap_leaves(node: BSPNode, pane_a: str, pane_b: str) -> tuple[BSPNode, bool]:
    """Swap positions of ``pane_a`` and ``pane_b`` within ``node``."""
    if (
        not pane_a
        or not pane_b
        or pane_a == pane_b
        or not contains_pane(node, pane_a)
        or not contains_pane(node, pane_b)
    ):
        return node, False

    def _walk(cur: BSPNode) -> BSPNode:
        if isinstance(cur, LeafNode):
            if cur.pane_id == pane_a:
                return LeafNode(pane_id=pane_b, leaf_id=cur.leaf_id)
            if cur.pane_id == pane_b:
                return LeafNode(pane_id=pane_a, leaf_id=cur.leaf_id)
            return cur
        return SplitNode(
            direction=cur.direction,
            first=_walk(cur.first),
            second=_walk(cur.second),
            ratio=cur.ratio,
        )

    return _walk(node), True


def compute_rects(
    node: BSPNode,
    bounds: tuple[float, float, float, float] = (0.0, 0.0, 1.0, 1.0),
) -> dict[str, tuple[float, float, float, float]]:
    """Compute normalized ``(x, y, width, height)`` bounds for each leaf in ``node``."""
    x, y, w, h = bounds
    if isinstance(node, LeafNode):
        return {node.pane_id: (x, y, w, h)}
    r = clamp_ratio(node.ratio)
    if node.direction == "horizontal":
        w1 = w * r
        w2 = w * (1.0 - r)
        rects = compute_rects(node.first, (x, y, w1, h))
        rects.update(compute_rects(node.second, (x + w1, y, w2, h)))
        return rects
    h1 = h * r
    h2 = h * (1.0 - r)
    rects = compute_rects(node.first, (x, y, w, h1))
    rects.update(compute_rects(node.second, (x, y + h1, w, h2)))
    return rects


def find_neighbor(
    node: BSPNode,
    source_pane_id: str,
    dx: int,
    dy: int,
) -> str | None:
    """Find best directional neighbor of ``source_pane_id`` for ``(dx, dy)``."""
    if dx == 0 and dy == 0:
        return None
    rects = compute_rects(node)
    src = rects.get(source_pane_id)
    if src is None:
        return None
    sx, sy, sw, sh = src
    scx = sx + sw * 0.5
    scy = sy + sh * 0.5
    eps = 1e-6

    candidates: list[tuple[tuple[float, float, float], str]] = []
    fallback_candidates: list[tuple[float, str]] = []

    for pid, (cx, cy, cw, ch) in rects.items():
        if pid == source_pane_id:
            continue
        ccx = cx + cw * 0.5
        ccy = cy + ch * 0.5
        if dx > 0:
            overlap_y = min(sy + sh, cy + ch) - max(sy, cy)
            if cx >= sx + sw - eps and overlap_y > eps:
                candidates.append(((cx - (sx + sw), -overlap_y, abs(ccy - scy)), pid))
            elif ccx > scx + eps:
                fallback_candidates.append(((ccx - scx) ** 2 + (ccy - scy) ** 2, pid))
        elif dx < 0:
            overlap_y = min(sy + sh, cy + ch) - max(sy, cy)
            if cx + cw <= sx + eps and overlap_y > eps:
                candidates.append(((sx - (cx + cw), -overlap_y, abs(ccy - scy)), pid))
            elif ccx < scx - eps:
                fallback_candidates.append(((ccx - scx) ** 2 + (ccy - scy) ** 2, pid))
        elif dy > 0:
            overlap_x = min(sx + sw, cx + cw) - max(sx, cx)
            if cy >= sy + sh - eps and overlap_x > eps:
                candidates.append(((cy - (sy + sh), -overlap_x, abs(ccx - scx)), pid))
            elif ccy > scy + eps:
                fallback_candidates.append(((ccx - scx) ** 2 + (ccy - scy) ** 2, pid))
        elif dy < 0:
            overlap_x = min(sx + sw, cx + cw) - max(sx, cx)
            if cy + ch <= sy + eps and overlap_x > eps:
                candidates.append(((sy - (cy + ch), -overlap_x, abs(ccx - scx)), pid))
            elif ccy < scy - eps:
                fallback_candidates.append(((ccx - scx) ** 2 + (ccy - scy) ** 2, pid))

    if candidates:
        candidates.sort(key=lambda item: item[0])
        return candidates[0][1]
    if fallback_candidates:
        fallback_candidates.sort(key=lambda item: item[0])
        return fallback_candidates[0][1]
    return None


def find_adjacent_non_source(node: BSPNode, source_pane_id: str) -> str | None:
    """Find an adjacent non-source tile to reuse when already at the 4-tile cap."""
    # Prefer direct BSP sibling leaf first.
    def _find_sibling(cur: BSPNode) -> str | None:
        if isinstance(cur, LeafNode):
            return None
        if isinstance(cur.first, LeafNode) and cur.first.pane_id == source_pane_id:
            leaves = leaf_pane_ids(cur.second)
            return leaves[0] if leaves else None
        if isinstance(cur.second, LeafNode) and cur.second.pane_id == source_pane_id:
            leaves = leaf_pane_ids(cur.first)
            return leaves[0] if leaves else None
        return _find_sibling(cur.first) or _find_sibling(cur.second)

    sibling = _find_sibling(node)
    if sibling and sibling != source_pane_id:
        return sibling

    for dx, dy in ((1, 0), (0, 1), (-1, 0), (0, -1)):
        neighbor = find_neighbor(node, source_pane_id, dx, dy)
        if neighbor and neighbor != source_pane_id:
            return neighbor

    for leaf in iter_leaves(node):
        if leaf.pane_id != source_pane_id:
            return leaf.pane_id
    return None


def adjust_split_ratio(
    node: BSPNode,
    target_pane_id: str,
    dx: int,
    dy: int,
    step: float = 0.05,
) -> tuple[BSPNode, bool]:
    """Adjust the nearest matching-axis ancestor ``SplitNode`` ratio for ``target_pane_id``."""
    if dx == 0 and dy == 0:
        return node, False
    axis: SplitDirection = "horizontal" if dx != 0 else "vertical"
    delta = (dx if axis == "horizontal" else dy) * abs(float(step))

    def _walk(cur: BSPNode) -> tuple[BSPNode, bool, bool]:
        # Returns (updated_node, contains_target, adjusted_already)
        if isinstance(cur, LeafNode):
            return cur, cur.pane_id == target_pane_id, False

        in_first = contains_pane(cur.first, target_pane_id)
        in_second = contains_pane(cur.second, target_pane_id)
        if not in_first and not in_second:
            return cur, False, False

        if in_first:
            new_first, _, adjusted = _walk(cur.first)
            new_second = cur.second
        else:
            new_first = cur.first
            new_second, _, adjusted = _walk(cur.second)

        if adjusted:
            return (
                SplitNode(
                    direction=cur.direction,
                    first=new_first,
                    second=new_second,
                    ratio=cur.ratio,
                ),
                True,
                True,
            )

        if cur.direction == axis:
            new_ratio = clamp_ratio(cur.ratio + delta)
            return (
                SplitNode(
                    direction=cur.direction,
                    first=new_first,
                    second=new_second,
                    ratio=new_ratio,
                ),
                True,
                True,
            )
        return (
            SplitNode(
                direction=cur.direction,
                first=new_first,
                second=new_second,
                ratio=cur.ratio,
            ),
            True,
            False,
        )

    updated, _, adjusted = _walk(node)
    return updated, adjusted


@dataclass
class WorkspaceSlotState:
    """Persisted BSP layout and focus/zoom state for one workspace slot (1..5)."""

    tree: BSPNode
    focused_pane_id: str
    zoomed_pane_id: str | None = None

    def sanitize(
        self,
        valid_pane_ids: Sequence[str] | set[str],
        fallback_pane_id: str,
    ) -> WorkspaceSlotState:
        valid_set = set(valid_pane_ids)
        leaves = leaf_pane_ids(self.tree)
        if not leaves or any(pid not in valid_set for pid in leaves):
            self.tree = node_from_dict(
                self.tree.to_dict(),
                valid_pane_ids=valid_pane_ids,
                fallback_pane_id=fallback_pane_id,
            )
            leaves = leaf_pane_ids(self.tree)
        if self.focused_pane_id not in leaves:
            self.focused_pane_id = leaves[0]
        if self.zoomed_pane_id is not None and self.zoomed_pane_id not in leaves:
            self.zoomed_pane_id = None
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "tree": self.tree.to_dict(),
            "focused_pane_id": self.focused_pane_id,
            "zoomed_pane_id": self.zoomed_pane_id,
        }

    @classmethod
    def from_dict(
        cls,
        data: Any,
        valid_pane_ids: Sequence[str] | set[str],
        fallback_pane_id: str,
    ) -> WorkspaceSlotState:
        if not isinstance(data, Mapping):
            leaf = LeafNode(pane_id=fallback_pane_id)
            return cls(tree=leaf, focused_pane_id=leaf.pane_id, zoomed_pane_id=None)
        raw_tree = data.get("tree", data)
        tree = node_from_dict(
            raw_tree,
            valid_pane_ids=valid_pane_ids,
            fallback_pane_id=fallback_pane_id,
        )
        leaves = leaf_pane_ids(tree)
        focused = str(data.get("focused_pane_id") or "").strip()
        if focused not in leaves:
            focused = leaves[0]
        zoomed_raw = data.get("zoomed_pane_id")
        zoomed = str(zoomed_raw).strip() if zoomed_raw else None
        if zoomed not in leaves:
            zoomed = None
        return cls(tree=tree, focused_pane_id=focused, zoomed_pane_id=zoomed)


@dataclass
class WorkspaceLayoutState:
    """Top-level persisted workspace layout state across all 5 slots."""

    mode: WorkspaceMode = "tabbed"
    active_workspace: int = 1
    active_pane_id: str = "tab-research"
    workspaces: dict[int, WorkspaceSlotState] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "active_workspace": self.active_workspace,
            "active_pane_id": self.active_pane_id,
            "workspaces": {
                str(slot): slot_state.to_dict()
                for slot, slot_state in sorted(self.workspaces.items())
            },
        }

    @classmethod
    def from_dict(
        cls,
        data: Any,
        valid_pane_ids: Sequence[str] | set[str],
        fallback_pane_id: str,
        *,
        mode_override: str | None = None,
    ) -> WorkspaceLayoutState:
        valid_set = set(valid_pane_ids)
        fb = fallback_pane_id if fallback_pane_id in valid_set else next(iter(valid_pane_ids), "tab-research")
        if not isinstance(data, Mapping):
            data = {}
        raw_mode = mode_override if mode_override is not None else data.get("mode", "tabbed")
        mode: WorkspaceMode = "tiling" if str(raw_mode or "").strip().lower() == "tiling" else "tabbed"

        raw_ws = data.get("active_workspace", 1)
        try:
            active_ws = int(raw_ws) if not isinstance(raw_ws, bool) else 1
        except (TypeError, ValueError):
            active_ws = 1
        if active_ws not in WORKSPACE_SLOTS:
            active_ws = 1

        raw_active_pane = str(data.get("active_pane_id") or "").strip()
        active_pane = raw_active_pane if raw_active_pane in valid_set else fb

        raw_workspaces = data.get("workspaces")
        slots: dict[int, WorkspaceSlotState] = {}
        if isinstance(raw_workspaces, Mapping):
            for key, raw_slot in raw_workspaces.items():
                try:
                    slot_num = int(key)
                except (TypeError, ValueError):
                    continue
                if slot_num not in WORKSPACE_SLOTS:
                    continue
                slots[slot_num] = WorkspaceSlotState.from_dict(
                    raw_slot,
                    valid_pane_ids=valid_pane_ids,
                    fallback_pane_id=fb,
                )
        return cls(
            mode=mode,
            active_workspace=active_ws,
            active_pane_id=active_pane,
            workspaces=slots,
        )


# ---------------------------------------------------------------------------
# Textual Widgets
# ---------------------------------------------------------------------------


class _SocTabbedContent(TabbedContent):
    """TabbedContent that ignores stale focus events from hidden panes."""

    def _on_tab_pane_focused(self, event: TabPane.Focused) -> None:
        if not event.tab_pane.display:
            event.prevent_default()
            event.stop()
            return
        super()._on_tab_pane_focused(event)


class SplitDivider(Static):
    """Draggable 1-cell resize sash placed between two children of a ``TileSplit``."""

    can_focus = False

    def __init__(self, direction: SplitDirection) -> None:
        clean_dir = _normalize_direction(direction)
        glyph = "│" if clean_dir == "horizontal" else "─"
        classes = f"split-divider -{clean_dir}"
        super().__init__(glyph, classes=classes)
        self.direction: SplitDirection = clean_dir
        self._dragging: bool = False

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button != 1:
            return
        self._dragging = True
        self.add_class("-dragging")
        self.capture_mouse(True)
        event.stop()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if not self._dragging:
            return
        parent = self.parent
        if not isinstance(parent, TileSplit):
            return
        region = parent.region
        if self.direction == "horizontal" and region.width > 0:
            raw_ratio = (event.screen_x - region.x) / float(region.width)
            parent.set_ratio(raw_ratio, persist=False)
        elif self.direction == "vertical" and region.height > 0:
            raw_ratio = (event.screen_y - region.y) / float(region.height)
            parent.set_ratio(raw_ratio, persist=False)
        event.stop()

    def on_mouse_up(self, event: events.MouseUp) -> None:
        if not self._dragging:
            return
        self._dragging = False
        self.remove_class("-dragging")
        self.capture_mouse(False)
        for anc in self.ancestors:
            if isinstance(anc, WorkspaceHost):
                slot = anc._slots.get(anc._active_workspace)
                if slot is not None:
                    anc._rendered_tree_dict = slot.tree.to_dict()
                anc.save_persisted_state()
                break
        event.stop()


class TileLeaf(Container):
    """Tiled container hosting a single live ``BaseSocPane`` widget."""

    can_focus = True

    def __init__(
        self,
        pane_id: str,
        *,
        leaf_id: str = "",
        title: str = "",
        focused: bool = False,
        zoomed: bool = False,
    ) -> None:
        classes = "tile-leaf"
        if focused:
            classes += " -focused"
        if zoomed:
            classes += " -zoomed"
        super().__init__(classes=classes)
        self.pane_id: str = pane_id
        self.leaf_id: str = leaf_id or uuid.uuid4().hex[:8]
        self._base_title: str = title or pane_id
        self.focused: bool = focused
        self.zoomed: bool = zoomed
        self.border_title = self._format_title()
        self.styles.border_title_align = "left"

    def _format_title(self) -> Content:
        text = f"{self._base_title} [ZOOM]" if self.zoomed else self._base_title
        return Content(text)

    def set_tile_focused(self, focused: bool) -> None:
        self.focused = bool(focused)
        self.set_class(self.focused, "-focused")

    def set_tile_zoomed(self, zoomed: bool) -> None:
        self.zoomed = bool(zoomed)
        self.set_class(self.zoomed, "-zoomed")
        self.border_title = self._format_title()

    def sync_compact_classes(self, width: int | None = None, height: int | None = None) -> None:
        w = int(self.size.width if width is None else width)
        h = int(self.size.height if height is None else height)
        if w <= 0 and h <= 0:
            return
        self.set_class(w < 96, "-compact-narrow")
        self.set_class(w < 96, "tile-narrow")
        self.set_class(w < 96 or h <= 24, "tile-compact")
        self.set_class(h <= 24, "tile-short")

    def on_mount(self) -> None:
        self.sync_compact_classes()

    def on_resize(self, event: events.Resize) -> None:
        self.sync_compact_classes(event.size.width, event.size.height)

    def _notify_host_focused(self) -> None:
        for anc in self.ancestors:
            if isinstance(anc, WorkspaceHost):
                anc._on_leaf_focused_from_ui(self.pane_id)
                break

    def on_focus(self, _event: events.Focus) -> None:
        self._notify_host_focused()

    def on_descendant_focus(self, _event: events.DescendantFocus) -> None:
        self._notify_host_focused()

    def on_mouse_down(self, _event: events.MouseDown) -> None:
        self._notify_host_focused()


class TileSplit(Container):
    """Binary split container hosting ``first``, ``SplitDivider``, and ``second``."""

    can_focus = False

    def __init__(
        self,
        direction: SplitDirection,
        first_widget: TileLeaf | TileSplit,
        second_widget: TileLeaf | TileSplit,
        *,
        ratio: float = DEFAULT_SPLIT_RATIO,
        split_node: SplitNode | None = None,
    ) -> None:
        clean_dir = _normalize_direction(direction)
        super().__init__(classes=f"tile-split -{clean_dir}")
        self.direction: SplitDirection = clean_dir
        self.ratio: float = clamp_ratio(ratio)
        self.split_node: SplitNode | None = split_node
        self.first_widget: TileLeaf | TileSplit = first_widget
        self.divider_widget: SplitDivider = SplitDivider(clean_dir)
        self.second_widget: TileLeaf | TileSplit = second_widget
        self._apply_fr_weights()

    def compose(self) -> ComposeResult:
        yield self.first_widget
        yield self.divider_widget
        yield self.second_widget

    def _apply_fr_weights(self) -> None:
        r1 = max(1, round(self.ratio * 1000))
        r2 = max(1, 1000 - r1)
        if self.direction == "horizontal":
            self.first_widget.styles.width = f"{r1}fr"
            self.first_widget.styles.height = "1fr"
            self.second_widget.styles.width = f"{r2}fr"
            self.second_widget.styles.height = "1fr"
        else:
            self.first_widget.styles.width = "1fr"
            self.first_widget.styles.height = f"{r1}fr"
            self.second_widget.styles.width = "1fr"
            self.second_widget.styles.height = f"{r2}fr"

    def set_ratio(self, ratio: float, *, persist: bool = True) -> float:
        self.ratio = clamp_ratio(ratio)
        if self.split_node is not None:
            self.split_node.ratio = self.ratio
        self._apply_fr_weights()
        self.refresh(layout=True)
        if persist:
            for anc in self.ancestors:
                if isinstance(anc, WorkspaceHost):
                    anc.save_persisted_state()
                    break
        return self.ratio


class PanePickerModal(ModalScreen[str | None]):
    """Quick pane picker modal opened via ``Alt+p`` in Tiling Mode."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "cancel", "Close", show=False),
        Binding("q", "cancel", "Close", show=False),
    ]

    DEFAULT_CSS: ClassVar[str] = """
    PanePickerModal {
        align: center middle;
        background: rgba(15, 19, 28, 0.65);
    }
    #pane-picker-box {
        width: 56;
        max-width: 90%;
        height: auto;
        max-height: 80%;
        border: solid #58a6ff;
        background: #171d2b;
        padding: 0;
    }
    #pane-picker-title {
        height: 1;
        width: 1fr;
        background: #1e273b;
        color: #f0f6ff;
        text-style: bold;
        padding: 0 1;
    }
    #pane-picker-options {
        width: 1fr;
        height: auto;
        max-height: 18;
        border: none;
        background: #171d2b;
    }
    """

    def __init__(
        self,
        panes: Sequence[tuple[str, str]],
        *,
        visible_panes: set[str] | None = None,
        focused_pane_id: str = "",
    ) -> None:
        super().__init__()
        self._panes: list[tuple[str, str]] = list(panes)
        self._visible_panes: set[str] = set(visible_panes or ())
        self._focused_pane_id: str = focused_pane_id

    def compose(self) -> ComposeResult:
        with Vertical(id="pane-picker-box"):
            yield Static("Switch Tile Pane (Enter to select, Esc to cancel)", id="pane-picker-title", markup=False)
            options: list[Option] = []
            for pane_id, title in self._panes:
                suffix = ""
                if pane_id == self._focused_pane_id:
                    suffix = " [Focused]"
                elif pane_id in self._visible_panes:
                    suffix = " [Visible]"
                options.append(Option(f"{title}{suffix}", id=pane_id))
            yield OptionList(*options, id="pane-picker-options", markup=False, compact=True)

    def on_mount(self) -> None:
        opt_list = self.query_one("#pane-picker-options", OptionList)
        if self._focused_pane_id:
            with contextlib.suppress(Exception):
                opt_list.highlighted = opt_list.get_option_index(self._focused_pane_id)
        opt_list.focus()

    @on(OptionList.OptionSelected, "#pane-picker-options")
    def handle_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        selected_id = str(event.option.id or "").strip()
        self.dismiss(selected_id or None)

    def on_click(self, event: events.Click) -> None:
        if event.button != 1:
            return
        box = self.query_one("#pane-picker-box", Vertical)
        if not box.region.contains(event.screen_x, event.screen_y):
            event.stop()
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class WorkspaceHost(Container):
    """Top-level workspace host managing Tabbed Mode and Linux-style BSP Tiling Mode."""

    class _SyncWorkspace(Message):
        """Internal async-drained message that synchronizes tiling DOM and runs callbacks."""

        def __init__(
            self,
            callbacks: Sequence[tuple[str, Callable[[BaseSocPane], None]]] = (),
            *,
            focus_pane: bool = True,
        ) -> None:
            super().__init__()
            self.callbacks: tuple[tuple[str, Callable[[BaseSocPane], None]], ...] = tuple(callbacks)
            self.focus_pane: bool = focus_pane

    class _CleanupTilingRoot(Message):
        """Internal async-drained message to clear hidden tiling containers in Tabbed Mode."""

    def __init__(
        self,
        *,
        initial_tab: str,
        tab_specs: Sequence[tuple[str, str, type[BaseSocPane]]],
        id: str = "workspace-host",
    ) -> None:
        super().__init__(id=id)
        self._initial_tab: str = initial_tab
        self._tab_specs: tuple[tuple[str, str, type[BaseSocPane]], ...] = tuple(tab_specs)
        self._titles: dict[str, str] = {tid: title for tid, title, _ in self._tab_specs}
        self._pane_classes: dict[str, type[BaseSocPane]] = {
            tid: cls for tid, _title, cls in self._tab_specs
        }
        self._mode: WorkspaceMode = "tabbed"
        self._active_workspace: int = 1
        self._active_pane_id: str = initial_tab
        self._slots: dict[int, WorkspaceSlotState] = {}
        self._leaf_widgets: dict[str, TileLeaf] = {}
        self._split_widgets: list[TileSplit] = []
        self._rebuilding: bool = False
        self._suppress_persisting: bool = False
        self._rendered_tree_dict: dict[str, Any] | None = None

    @property
    def mode(self) -> WorkspaceMode:
        return self._mode

    @property
    def active_workspace(self) -> int:
        return self._active_workspace

    @property
    def workspaces(self) -> dict[int, BSPNode]:
        return {slot: slot_state.tree for slot, slot_state in self._slots.items()}

    @property
    def active_pane_id(self) -> str:
        if self._mode == "tabbed":
            with contextlib.suppress(Exception):
                tabs = self.query_one("#main-tabs", TabbedContent)
                if tabs.active:
                    self._active_pane_id = str(tabs.active)
                    return self._active_pane_id
            return self._active_pane_id
        slot = self._slots.get(self._active_workspace)
        if slot is not None:
            return slot.focused_pane_id
        return self._active_pane_id

    @property
    def focused_pane_id(self) -> str:
        return self.active_pane_id

    @property
    def zoomed(self) -> bool:
        if self._mode != "tiling":
            return False
        slot = self._slots.get(self._active_workspace)
        return bool(slot is not None and slot.zoomed_pane_id is not None)

    def compose(self) -> ComposeResult:
        with _SocTabbedContent(initial=self._initial_tab, id="main-tabs"):
            for tab_id, title, pane_cls in self._tab_specs:
                with TabPane(title, id=tab_id):
                    if tab_id == self._initial_tab:
                        yield pane_cls()
        yield Container(id="tiling-root")

    def on_mount(self) -> None:
        tiling_root = self.query_one("#tiling-root", Container)
        tiling_root.display = self._mode == "tiling"
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.display = self._mode == "tabbed"

    def _visible_tab_ids(self) -> tuple[str, ...]:
        visible = getattr(self.app, "visible_tab_ids", None)
        if isinstance(visible, (tuple, list)):
            return tuple(str(x) for x in visible)
        return tuple(self._titles.keys())

    def _is_tab_visible(self, tab_id: str) -> bool:
        fn = getattr(self.app, "is_tab_visible", None)
        if callable(fn):
            return bool(fn(tab_id))
        return tab_id in self._titles

    def _fallback_pane_id(self) -> str:
        last_user = str(getattr(self.app, "_last_user_tab", "") or "")
        visible = self._visible_tab_ids()
        if last_user and last_user in visible:
            return last_user
        if self._initial_tab in visible:
            return self._initial_tab
        return visible[0] if visible else "tab-research"

    def _ensure_slot(self, slot: int, *, seed_pane_id: str | None = None) -> WorkspaceSlotState:
        visible = self._visible_tab_ids()
        fb = seed_pane_id if (seed_pane_id and seed_pane_id in visible) else self._fallback_pane_id()
        existing = self._slots.get(slot)
        if existing is None:
            existing = WorkspaceSlotState(tree=LeafNode(pane_id=fb), focused_pane_id=fb)
            self._slots[slot] = existing
        else:
            existing.sanitize(visible, fb)
        return existing

    def _ensure_active_slot(self) -> WorkspaceSlotState:
        return self._ensure_slot(self._active_workspace, seed_pane_id=self._active_pane_id)

    def _next_unused_pane_id(self, tree: BSPNode) -> str | None:
        used = set(leaf_pane_ids(tree))
        for candidate in self._visible_tab_ids():
            if candidate not in used:
                return candidate
        return None

    def _get_tab_pane(self, pane_id: str) -> TabPane | None:
        with contextlib.suppress(Exception):
            return self.query_one(f"#{pane_id}", TabPane)
        return None

    def _get_mounted_pane(self, pane_id: str) -> BaseSocPane | None:
        getter = getattr(self.app, "_get_mounted_pane", None)
        if callable(getter):
            pane = getter(pane_id)
            if pane is not None:
                return cast("BaseSocPane", pane)
        return None

    def _reparent_widget(self, pane: Widget, new_parent: Widget) -> None:
        if pane.parent is new_parent:
            return
        old_parent = pane.parent
        if old_parent is not None:
            old_parent._nodes._remove(pane)
            pane._detach()
            old_parent.refresh(layout=True)
        new_parent._nodes._append(pane)
        pane._attach(new_parent)
        pane.display = True
        if self.app is not None:
            self.app.stylesheet.update(pane)
        new_parent.refresh(layout=True)

    def _park_all_panes(self) -> None:
        from soclens.tui.screens.base import BaseSocPane

        with contextlib.suppress(Exception):
            tiling_root = self.query_one("#tiling-root", Container)
            for pane in list(tiling_root.query(BaseSocPane)):
                pane_id = self._pane_id_for_widget(pane)
                if not pane_id:
                    continue
                home = self._get_tab_pane(pane_id)
                if home is not None:
                    self._reparent_widget(pane, home)

    def _pane_id_for_widget(self, pane: Widget) -> str:
        for pid, cls in self._pane_classes.items():
            if isinstance(pane, cls):
                return pid
        return ""

    def load_persisted_state(self, payload: Mapping[str, Any] | None = None) -> None:
        """Load and sanitize workspace mode & BSP layouts from ``StorageManager``."""
        data: Mapping[str, Any]
        if payload is None:
            storage = getattr(self.app, "storage", None)
            if storage is None or not hasattr(storage, "load_workspace_layout"):
                return
            try:
                loaded = storage.load_workspace_layout()
                data = loaded if isinstance(loaded, Mapping) else {}
            except Exception:
                return
        else:
            data = payload

        raw_mode = str(data.get("mode") or "tabbed").strip().lower()
        raw_state = data.get("state")
        state_map = raw_state if isinstance(raw_state, Mapping) else {}

        parsed = WorkspaceLayoutState.from_dict(
            state_map,
            valid_pane_ids=self._visible_tab_ids(),
            fallback_pane_id=self._fallback_pane_id(),
            mode_override=raw_mode,
        )
        self._slots = dict(parsed.workspaces)
        self._active_workspace = parsed.active_workspace
        self._active_pane_id = parsed.active_pane_id

        self._suppress_persisting = True
        try:
            self.set_mode(parsed.mode, persist=False)
        finally:
            self._suppress_persisting = False

    def save_persisted_state(self) -> dict[str, Any] | None:
        """Persist current mode & BSP workspaces to ``self.app.storage`` dynamically."""
        if self._suppress_persisting:
            return None
        storage = getattr(self.app, "storage", None)
        if storage is None or not hasattr(storage, "save_workspace_layout"):
            return None
        layout_state = WorkspaceLayoutState(
            mode=self._mode,
            active_workspace=self._active_workspace,
            active_pane_id=self.active_pane_id,
            workspaces=dict(self._slots),
        )
        try:
            return cast(
                dict[str, Any],
                storage.save_workspace_layout(
                    mode=self._mode,
                    state=layout_state.to_dict(),
                ),
            )
        except Exception:
            return None

    def _schedule_sync(
        self,
        callbacks: Sequence[tuple[str, Callable[[BaseSocPane], None]]] = (),
        *,
        focus_pane: bool = True,
    ) -> None:
        self.post_message(self._SyncWorkspace(callbacks=callbacks, focus_pane=focus_pane))

    def _build_widget_tree(self, node: BSPNode, focused_id: str, zoomed_id: str | None) -> TileLeaf | TileSplit:
        if isinstance(node, LeafNode):
            title = self._titles.get(node.pane_id, node.pane_id)
            leaf = TileLeaf(
                node.pane_id,
                leaf_id=node.leaf_id,
                title=title,
                focused=(node.pane_id == focused_id),
                zoomed=(zoomed_id == node.pane_id),
            )
            self._leaf_widgets[node.pane_id] = leaf
            return leaf
        first_w = self._build_widget_tree(node.first, focused_id, zoomed_id)
        second_w = self._build_widget_tree(node.second, focused_id, zoomed_id)
        split_w = TileSplit(
            node.direction,
            first_w,
            second_w,
            ratio=node.ratio,
            split_node=node,
        )
        self._split_widgets.append(split_w)
        return split_w

    def _apply_zoom_visuals(self, slot_state: WorkspaceSlotState) -> None:
        zoomed_id = slot_state.zoomed_pane_id
        for leaf in self._leaf_widgets.values():
            if zoomed_id is None:
                leaf.display = True
                leaf.set_tile_zoomed(False)
            elif leaf.pane_id == zoomed_id:
                leaf.display = True
                leaf.set_tile_zoomed(True)
                leaf.styles.width = "1fr"
                leaf.styles.height = "1fr"
            else:
                leaf.display = False
                leaf.set_tile_zoomed(False)

        for split_w in self._split_widgets:
            split_w.divider_widget.display = zoomed_id is None
            if zoomed_id is None:
                split_w.first_widget.display = True
                split_w.second_widget.display = True
                split_w.set_ratio(split_w.ratio, persist=False)
            else:
                in_first = contains_pane(split_w.split_node.first, zoomed_id) if split_w.split_node else False
                in_second = contains_pane(split_w.split_node.second, zoomed_id) if split_w.split_node else False
                if in_first and not in_second:
                    split_w.first_widget.display = True
                    split_w.first_widget.styles.width = "1fr"
                    split_w.first_widget.styles.height = "1fr"
                    split_w.second_widget.display = False
                elif in_second and not in_first:
                    split_w.second_widget.display = True
                    split_w.second_widget.styles.width = "1fr"
                    split_w.second_widget.styles.height = "1fr"
                    split_w.first_widget.display = False
                else:
                    split_w.first_widget.display = False
                    split_w.second_widget.display = False

    def _apply_focus_visuals(self, focused_id: str, *, move_focus: bool = False) -> None:
        for pid, leaf in self._leaf_widgets.items():
            leaf.set_tile_focused(pid == focused_id)
        if move_focus:
            target = self._leaf_widgets.get(focused_id)
            if target is not None and target.display:
                with contextlib.suppress(Exception):
                    target.focus()

    def _on_leaf_focused_from_ui(self, pane_id: str) -> None:
        if self._mode != "tiling" or self._rebuilding:
            return
        slot = self._slots.get(self._active_workspace)
        if slot is None or not contains_pane(slot.tree, pane_id):
            return
        if slot.focused_pane_id == pane_id:
            return
        slot.focused_pane_id = pane_id
        self._active_pane_id = pane_id
        self._apply_focus_visuals(pane_id, move_focus=False)
        self.save_persisted_state()

    @on(_CleanupTilingRoot)
    async def _on_cleanup_tiling_root(self, _event: _CleanupTilingRoot) -> None:
        if self._mode == "tabbed":
            self._park_all_panes()
            tiling_root = self.query_one("#tiling-root", Container)
            await tiling_root.remove_children()
            self._rendered_tree_dict = None

    @on(_SyncWorkspace)
    async def _on_sync_workspace(self, event: _SyncWorkspace) -> None:
        if self._mode != "tiling" or getattr(self.app, "is_shutting_down", False):
            return
        slot_state = self._ensure_active_slot()
        tiling_root = self.query_one("#tiling-root", Container)
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.display = False
        tiling_root.display = True

        target_tree_dict = slot_state.tree.to_dict()
        target_leaves = leaf_pane_ids(slot_state.tree)
        current_order = list(self._leaf_widgets.keys())
        need_rebuild = (
            not tiling_root.children
            or current_order != target_leaves
            or self._rendered_tree_dict != target_tree_dict
        )

        self._rebuilding = True
        try:
            if need_rebuild:
                self._park_all_panes()
                await tiling_root.remove_children()
                self._leaf_widgets = {}
                self._split_widgets = []
                root_widget = self._build_widget_tree(
                    slot_state.tree,
                    slot_state.focused_pane_id,
                    slot_state.zoomed_pane_id,
                )
                await tiling_root.mount(root_widget)

                ensure_fn = getattr(self.app, "ensure_tab_mounted", None)
                for leaf_node in iter_leaves(slot_state.tree):
                    pane = self._get_mounted_pane(leaf_node.pane_id)
                    if pane is None and callable(ensure_fn):
                        pane = await ensure_fn(leaf_node.pane_id)
                    leaf_w = self._leaf_widgets.get(leaf_node.pane_id)
                    if pane is not None and leaf_w is not None:
                        self._reparent_widget(pane, leaf_w)
                        with contextlib.suppress(Exception):
                            pane.on_tab_activated()
                self._rendered_tree_dict = target_tree_dict

            self._apply_zoom_visuals(slot_state)
            self._apply_focus_visuals(slot_state.focused_pane_id, move_focus=event.focus_pane)
            tiling_root.refresh(layout=True)

            for target_id, cb in event.callbacks:
                pane = self._get_mounted_pane(target_id)
                if pane is None:
                    ensure_fn = getattr(self.app, "ensure_tab_mounted", None)
                    if callable(ensure_fn):
                        pane = await ensure_fn(target_id)
                if pane is not None:
                    try:
                        cb(pane)
                    except Exception as exc:
                        rec_log = getattr(self.app, "record_log", None)
                        if callable(rec_log):
                            rec_log(
                                f"Tile callback failed for {target_id}: {exc}",
                                level="ERROR",
                                source="tui",
                                logger_name="WorkspaceHost",
                            )
        finally:
            self._rebuilding = False

    def set_mode(self, mode: str, *, persist: bool = True) -> WorkspaceMode:
        """Switch workspace mode between ``'tabbed'`` and ``'tiling'``."""
        target_mode: WorkspaceMode = "tiling" if str(mode).strip().lower() == "tiling" else "tabbed"
        tabs = self.query_one("#main-tabs", TabbedContent)
        tiling_root = self.query_one("#tiling-root", Container)

        if target_mode == "tiling":
            current_active = str(tabs.active or self._active_pane_id or self._fallback_pane_id())
            if not self._is_tab_visible(current_active):
                current_active = self._fallback_pane_id()
            if self._active_workspace not in self._slots:
                self._ensure_slot(self._active_workspace, seed_pane_id=current_active)
            else:
                slot_state = self._ensure_active_slot()
                if contains_pane(slot_state.tree, current_active):
                    slot_state.focused_pane_id = current_active
            self._mode = "tiling"
            self._active_pane_id = self._slots[self._active_workspace].focused_pane_id
            tabs.display = False
            tiling_root.display = True
            self._schedule_sync(focus_pane=True)
        else:
            prev_active = self.active_pane_id
            if not self._is_tab_visible(prev_active):
                prev_active = self._fallback_pane_id()
            self._park_all_panes()
            self._leaf_widgets.clear()
            self._split_widgets.clear()
            self._rendered_tree_dict = None
            self._mode = "tabbed"
            self._active_pane_id = prev_active
            tiling_root.display = False
            tabs.display = True
            if tabs.active != prev_active:
                tabs.active = prev_active
            self.post_message(self._CleanupTilingRoot())
            focus_tabs = getattr(self.app, "_focus_main_tabs", None)
            if callable(focus_tabs):
                focus_tabs()

        if persist:
            self.save_persisted_state()
        with contextlib.suppress(Exception):
            self.app.refresh_bindings()
        return self._mode

    def toggle_mode(self, *, persist: bool = True) -> WorkspaceMode:
        """Toggle between Tabbed Mode and BSP Tiling Mode."""
        return self.set_mode("tiling" if self._mode == "tabbed" else "tabbed", persist=persist)

    def switch_to_pane(
        self,
        pane_id: str,
        *,
        auto_enable_admin: bool = False,
        on_ready: Callable[[BaseSocPane], None] | None = None,
    ) -> bool:
        """Activate ``pane_id`` in Tabbed Mode or switch/focus it in Tiling Mode."""
        if pane_id not in self._titles:
            return False
        if not self._is_tab_visible(pane_id):
            if auto_enable_admin:
                set_vm = getattr(self.app, "set_view_mode", None)
                if callable(set_vm):
                    set_vm("admin")
            else:
                if self.app is not None:
                    self.app.notify(
                        "Enable Admin View (F2) to access this tab.",
                        title="Admin View Required",
                        severity="warning",
                    )
                return False

        if self._mode == "tabbed":
            self._active_pane_id = pane_id
            activate_tabbed = getattr(self.app, "_activate_tabbed_pane", None)
            if callable(activate_tabbed):
                return bool(activate_tabbed(pane_id, on_ready=on_ready))
            tabs = self.query_one("#main-tabs", TabbedContent)
            tabs.active = pane_id
            return True

        slot_state = self._ensure_active_slot()
        if contains_pane(slot_state.tree, pane_id):
            slot_state.focused_pane_id = pane_id
            if slot_state.zoomed_pane_id is not None and slot_state.zoomed_pane_id != pane_id:
                slot_state.zoomed_pane_id = pane_id
            self._active_pane_id = pane_id
            self._apply_zoom_visuals(slot_state)
            self._apply_focus_visuals(pane_id, move_focus=True)
            self.save_persisted_state()
            if on_ready is not None:
                pane = self._get_mounted_pane(pane_id)
                if pane is not None:
                    on_ready(pane)
                else:
                    self._schedule_sync(callbacks=[(pane_id, on_ready)], focus_pane=True)
            return True

        # Replace the focused leaf's pane with pane_id (preserving BSP layout).
        new_tree, changed = replace_leaf(slot_state.tree, slot_state.focused_pane_id, pane_id)
        if not changed:
            return False
        slot_state.tree = new_tree
        slot_state.focused_pane_id = pane_id
        if slot_state.zoomed_pane_id is not None:
            slot_state.zoomed_pane_id = pane_id
        self._active_pane_id = pane_id
        self.save_persisted_state()
        callbacks = [(pane_id, on_ready)] if on_ready is not None else []
        self._schedule_sync(callbacks=callbacks, focus_pane=True)
        return True

    def split_tile(
        self,
        direction: SplitDirection,
        pane_id: str | None = None,
        *,
        on_ready: Callable[[BaseSocPane], None] | None = None,
    ) -> bool:
        """Split the focused tile along ``direction`` (capped at 4 tiles)."""
        if self._mode != "tiling":
            return False
        slot_state = self._ensure_active_slot()
        if count_leaves(slot_state.tree) >= MAX_TILES_PER_WORKSPACE:
            if self.app is not None:
                self.app.notify(
                    f"Maximum of {MAX_TILES_PER_WORKSPACE} tiles per workspace reached.",
                    title="Tile Limit",
                    severity="warning",
                )
            return False

        target_new = pane_id
        if target_new is not None:
            if target_new not in self._titles or not self._is_tab_visible(target_new):
                return False
            if contains_pane(slot_state.tree, target_new):
                return self.switch_to_pane(target_new, on_ready=on_ready)
        else:
            target_new = self._next_unused_pane_id(slot_state.tree)
        if not target_new:
            return False

        new_tree, split_ok = split_leaf(
            slot_state.tree,
            slot_state.focused_pane_id,
            target_new,
            direction,
        )
        if not split_ok:
            return False

        slot_state.tree = new_tree
        slot_state.focused_pane_id = target_new
        slot_state.zoomed_pane_id = None
        self._active_pane_id = target_new
        self.save_persisted_state()
        callbacks = [(target_new, on_ready)] if on_ready is not None else []
        self._schedule_sync(callbacks=callbacks, focus_pane=True)
        return True

    def focus_direction(self, dx: int, dy: int) -> bool:
        """Move focus to the neighboring tile in direction ``(dx, dy)``."""
        if self._mode != "tiling":
            return False
        slot_state = self._ensure_active_slot()
        neighbor = find_neighbor(slot_state.tree, slot_state.focused_pane_id, dx, dy)
        if not neighbor:
            return False
        slot_state.focused_pane_id = neighbor
        if slot_state.zoomed_pane_id is not None:
            slot_state.zoomed_pane_id = neighbor
            self._apply_zoom_visuals(slot_state)
        self._active_pane_id = neighbor
        self._apply_focus_visuals(neighbor, move_focus=True)
        self.save_persisted_state()
        return True

    def swap_direction(self, dx: int, dy: int) -> bool:
        """Swap the focused tile with its neighbor in direction ``(dx, dy)``."""
        if self._mode != "tiling":
            return False
        slot_state = self._ensure_active_slot()
        neighbor = find_neighbor(slot_state.tree, slot_state.focused_pane_id, dx, dy)
        if not neighbor:
            return False
        new_tree, swapped = swap_leaves(slot_state.tree, slot_state.focused_pane_id, neighbor)
        if not swapped:
            return False
        slot_state.tree = new_tree
        slot_state.zoomed_pane_id = None
        self.save_persisted_state()
        self._schedule_sync(focus_pane=True)
        return True

    def resize_direction(self, dx: int, dy: int, step: float = 0.05) -> bool:
        """Adjust the nearest matching-axis split ratio for the focused tile."""
        if self._mode != "tiling":
            return False
        slot_state = self._ensure_active_slot()
        new_tree, adjusted = adjust_split_ratio(
            slot_state.tree,
            slot_state.focused_pane_id,
            dx,
            dy,
            step=step,
        )
        if not adjusted:
            return False
        slot_state.tree = new_tree
        # Apply new ratios directly to existing TileSplit widgets in-place.
        self._sync_split_ratios_in_dom(new_tree)
        self.save_persisted_state()
        return True

    def _sync_split_ratios_in_dom(self, node: BSPNode) -> None:
        # Walk SplitNodes in post-order matching _build_widget_tree append order.
        split_nodes: list[SplitNode] = []

        def _collect(cur: BSPNode) -> None:
            if isinstance(cur, SplitNode):
                _collect(cur.first)
                _collect(cur.second)
                split_nodes.append(cur)

        _collect(node)
        if len(split_nodes) != len(self._split_widgets):
            self._schedule_sync(focus_pane=True)
            return
        for split_w, s_node in zip(self._split_widgets, split_nodes, strict=False):
            split_w.split_node = s_node
            split_w.set_ratio(s_node.ratio, persist=False)
        self._rendered_tree_dict = node.to_dict()

    def toggle_zoom(self) -> bool:
        """Toggle zoom/maximize on the currently focused tile."""
        if self._mode != "tiling":
            return False
        slot_state = self._ensure_active_slot()
        if slot_state.zoomed_pane_id is None:
            slot_state.zoomed_pane_id = slot_state.focused_pane_id
        else:
            slot_state.zoomed_pane_id = None
        self._apply_zoom_visuals(slot_state)
        self._apply_focus_visuals(slot_state.focused_pane_id, move_focus=True)
        self.save_persisted_state()
        return True

    def close_focused_tile(self) -> bool:
        """Close the focused tile unless it is the last remaining tile."""
        if self._mode != "tiling":
            return False
        slot_state = self._ensure_active_slot()
        if count_leaves(slot_state.tree) <= 1:
            if self.app is not None:
                self.app.notify(
                    "Cannot close the last tile (press Alt+t for Tabbed Mode or q to Quit).",
                    title="Tile Protected",
                    severity="warning",
                )
            return False
        new_tree, removed = remove_leaf(slot_state.tree, slot_state.focused_pane_id)
        if not removed or new_tree is None:
            return False
        leaves = leaf_pane_ids(new_tree)
        slot_state.tree = new_tree
        slot_state.focused_pane_id = leaves[0]
        slot_state.zoomed_pane_id = None
        self._active_pane_id = slot_state.focused_pane_id
        self.save_persisted_state()
        self._schedule_sync(focus_pane=True)
        return True

    def switch_workspace(self, slot: int) -> bool:
        """Switch active workspace among named slots ``1..5``."""
        if isinstance(slot, bool) or not isinstance(slot, int) or slot not in WORKSPACE_SLOTS:
            raise ValueError(f"Workspace slot must be an integer in 1..5, got {slot!r}")
        if slot == self._active_workspace and self._active_workspace in self._slots:
            return True
        self._active_workspace = slot
        slot_state = self._ensure_slot(slot, seed_pane_id=self._fallback_pane_id())
        self._active_pane_id = slot_state.focused_pane_id
        self.save_persisted_state()
        if self._mode == "tiling":
            self._schedule_sync(focus_pane=True)
        return True

    def dispatch_pivot_tile(
        self,
        source_pane_id: str,
        target_pane_id: str,
        on_ready: Callable[[BaseSocPane], None] | None = None,
    ) -> bool:
        """Route a live cross-tile pivot within the 4-tile workspace cap."""
        if target_pane_id not in self._titles or not self._is_tab_visible(target_pane_id):
            if self.app is not None and target_pane_id in self._titles:
                self.app.notify(
                    "Enable Admin View (F2) to access this tab.",
                    title="Admin View Required",
                    severity="warning",
                )
            return False

        if self._mode != "tiling":
            return self.switch_to_pane(target_pane_id, on_ready=on_ready)

        slot_state = self._ensure_active_slot()
        callbacks: list[tuple[str, Callable[[BaseSocPane], None]]] = (
            [(target_pane_id, on_ready)] if on_ready is not None else []
        )

        # 1) Target already visible -> update in place & focus without adding a tile.
        if contains_pane(slot_state.tree, target_pane_id):
            slot_state.focused_pane_id = target_pane_id
            if slot_state.zoomed_pane_id is not None and slot_state.zoomed_pane_id != target_pane_id:
                slot_state.zoomed_pane_id = None
            self._active_pane_id = target_pane_id
            self.save_persisted_state()
            self._schedule_sync(callbacks=callbacks, focus_pane=True)
            return True

        anchor = (
            source_pane_id
            if source_pane_id and contains_pane(slot_state.tree, source_pane_id)
            else slot_state.focused_pane_id
        )

        # 2) Fewer than 4 tiles -> auto-split adjacent to source tile.
        if count_leaves(slot_state.tree) < MAX_TILES_PER_WORKSPACE:
            rects = compute_rects(slot_state.tree)
            _, _, aw, ah = rects.get(anchor, (0.0, 0.0, 1.0, 1.0))
            split_dir: SplitDirection = "horizontal" if aw >= ah * 0.85 else "vertical"
            if count_leaves(slot_state.tree) == 1:
                split_dir = "horizontal"
            new_tree, ok = split_leaf(slot_state.tree, anchor, target_pane_id, split_dir)
            if not ok:
                return False
            slot_state.tree = new_tree
            slot_state.focused_pane_id = target_pane_id
            slot_state.zoomed_pane_id = None
            self._active_pane_id = target_pane_id
            self.save_persisted_state()
            self._schedule_sync(callbacks=callbacks, focus_pane=True)
            return True

        # 3) Already at 4-tile cap -> reuse an adjacent non-source tile.
        victim = find_adjacent_non_source(slot_state.tree, anchor)
        if not victim:
            return False
        new_tree, ok = replace_leaf(slot_state.tree, victim, target_pane_id)
        if not ok:
            return False
        slot_state.tree = new_tree
        slot_state.focused_pane_id = target_pane_id
        slot_state.zoomed_pane_id = None
        self._active_pane_id = target_pane_id
        self.save_persisted_state()
        self._schedule_sync(callbacks=callbacks, focus_pane=True)
        return True

    def on_view_mode_changed(self, _view_mode: str) -> None:
        """Sanitize all workspace slots when toggling between User and Admin view."""
        visible = self._visible_tab_ids()
        fb = self._fallback_pane_id()
        changed_active = False
        changed_any = False
        for slot_num, slot_state in list(self._slots.items()):
            before = leaf_pane_ids(slot_state.tree)
            slot_state.sanitize(visible, fb)
            after = leaf_pane_ids(slot_state.tree)
            if before != after:
                changed_any = True
                if slot_num == self._active_workspace:
                    changed_active = True

        if not self._is_tab_visible(self._active_pane_id):
            self._active_pane_id = fb
            changed_any = True

        if self._mode == "tiling":
            active_slot = self._ensure_active_slot()
            self._active_pane_id = active_slot.focused_pane_id
            if changed_active:
                self._schedule_sync(focus_pane=True)
        if changed_any:
            self.save_persisted_state()
