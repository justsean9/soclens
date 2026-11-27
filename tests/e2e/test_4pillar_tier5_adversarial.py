"""Tier-5 white-box adversarial regression suite covering G1-G11 across Pillars 1-4 and packaging."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import threading
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import tests.e2e.pillar_mocks as _mocks
from soclens.agent_audit import redact_sensitive_data
from soclens.agent_guards import PromptAndSecretGuard
from soclens.agent_tools import ReadOnlyToolRegistry, ReadOnlyToolSpec, validate_readonly_spl
from soclens.bundler import create_bundle
from soclens.storage import DatabaseConfig, StorageManager
from soclens.tui.screens.splunk_es import SplunkESPane
from soclens.tui.tiling import TileLeaf
from tests.e2e.pillar_mocks import (
    create_web_test_client,
    exchange_web_auth,
    install_mock_db_drivers,
    make_pillar_app,
    press_tile_key,
)

# Re-export shared fixtures for pytest discovery.
v21_workspace = _mocks.v21_workspace
agentic_workspace = _mocks.agentic_workspace
pillar_workspace = _mocks.pillar_workspace
mock_rf_server = _mocks.mock_rf_server
mock_splunk_es_server = _mocks.mock_splunk_es_server
mock_s1_server = _mocks.mock_s1_server
mock_agentic_llm_server = _mocks.mock_agentic_llm_server
mock_osint_server = _mocks.mock_osint_server
run_cli = _mocks.run_cli

pytestmark = [pytest.mark.e2e, pytest.mark.tier5]

_REPO_ROOT = Path(__file__).resolve().parents[2]


# T5-01 (G1): ReadOnlyToolRegistry blocks case & whitespace variants of FORBIDDEN_MUTATING_METHOD_NAMES
@pytest.mark.feature("F2")
def test_t5_01_readonly_registry_blocks_case_and_whitespace_mutating_variants() -> None:
    schema = {"type": "object", "properties": {}}
    reg = ReadOnlyToolRegistry()

    def Update_Site(**kwargs: Any) -> dict[str, Any]:
        return {}

    candidates = [
        ReadOnlyToolSpec(
            name="CREATE_USER",
            description="d",
            parameters_schema=schema,
            source_category="s1",
            handler=lambda **kw: {},
        ),
        ReadOnlyToolSpec(
            name=" \tdisconnect_agent\n ",
            description="d",
            parameters_schema=schema,
            source_category="s1",
            handler=lambda **kw: {},
        ),
        ReadOnlyToolSpec(
            name="safe_name_1",
            description="d",
            parameters_schema=schema,
            source_category="s1",
            handler=Update_Site,
        ),
        ReadOnlyToolSpec(
            name="safe_name_2",
            description="d",
            parameters_schema=schema,
            source_category="s1",
            handler=lambda **kw: {},
            underlying_methods=(" Update_Notable ",),
        ),
        ReadOnlyToolSpec(
            name="safe_name_3",
            description="d",
            parameters_schema=schema,
            source_category="s1",
            handler=lambda **kw: {},
            underlying_methods=("CREATE_LIST",),
        ),
    ]
    for spec in candidates:
        with pytest.raises(ValueError):
            reg.register(spec)


# T5-02 (G2 + G3): agent_audit glpat- redaction & PromptAndSecretGuard NFKC fullwidth secret scrubbing
@pytest.mark.feature("F4")
@pytest.mark.feature("F9")
def test_t5_02_glpat_prose_and_nfkc_fullwidth_secrets_redacted(pillar_workspace: Path) -> None:
    glpat = "-".join(("glpat", "AbCdEf1234567890xyzw"))
    audit_out = redact_sensitive_data(f"GitLab token is {glpat} in prose")
    assert glpat not in str(audit_out)

    guard = PromptAndSecretGuard()
    fw_sk = "\uff53\uff4b\uff0d" + "AbCdEfGhIjKlMnOpQrSt1234"
    fw_akia = "\uff21\uff2b\uff29\uff21" + "IOSFODNN7EXAMPLE"
    fw_ghp = "\uff47\uff48\uff50\uff3f" + "1234567890abcdef1234"
    fw_glpat = "\uff47\uff4c\uff50\uff41\uff54\uff0d" + "AbCdEf1234567890xyzw"

    for fw_secret, pid, raw_prefix in (
        (fw_sk, "api_secret_key_leaked", "sk-AbCdEf"),
        (fw_akia, "aws_access_key_leaked", "AKIAIOSFODNN7EXAMPLE"),
        (fw_ghp, "github_token_leaked", "ghp_123456"),
        (fw_glpat, "gitlab_token_leaked", "glpat-AbCdEf"),
    ):
        res = guard.scan_candidate(f"Fullwidth secret: {fw_secret}")
        assert any(f["pattern_id"] == pid for f in res.findings)
        assert fw_secret not in res.redacted_content
        assert raw_prefix not in res.redacted_content


# T5-03 (G4): Web SSE log events & /learn must redact secrets including NFKC & glpat-
@pytest.mark.feature("F4")
@pytest.mark.feature("F13")
def test_t5_03_web_sse_logs_and_learn_redact_all_secrets(pillar_workspace: Path) -> None:
    client, app, token = create_web_test_client(pillar_workspace)
    try:
        csrf_hdrs = exchange_web_auth(client, token)
        rt = app.state.runtime

        async def _capture_sse_log() -> list[dict[str, Any]]:
            sub = rt.sse_bus.subscribe()
            try:
                logging.getLogger("soclens.t5").warning(
                    "Secrets " + "-".join(("glpat", "SecretToken1234567890")) + " sk-OpenAISecretKey12345678 "
                    "postgresql://admin:SuperSecretPass@pg.internal/db vault://secret/data/rf#token"
                )
                await asyncio.sleep(0.05)
                out: list[dict[str, Any]] = []
                while not sub.queue.empty():
                    item = sub.queue.get_nowait()
                    if item is not None and item[0] == "log":
                        out.append(item[1])
                return out
            finally:
                rt.sse_bus.unsubscribe(sub)

        events = asyncio.run(_capture_sse_log())
        assert events, "Expected SSE log frame"
        msg = events[-1]["message"]
        for secret_frag in (
            "-".join(("glpat", "SecretToken1234567890")),
            "sk-OpenAISecretKey12345678",
            "SuperSecretPass",
            "vault://secret/data/rf#token",
        ):
            assert secret_frag not in msg

        fw_sk = "\uff53\uff4b\uff0d" + "AbCdEfGhIjKlMnOpQrSt1234"
        r = client.post(
            "/api/ai/chat/stream",
            json={
                "prompt": f"/learn Host web-01 uses {fw_sk} and " + "-".join(("glpat", "AbCdEf1234567890xyzw")),
                "confirm_learn": True,
            },
            headers=csrf_hdrs,
        )
        assert r.status_code == 200
        entries = rt.learning_manager.list_entries()
        assert entries
        assert fw_sk not in entries[0].content
        assert "sk-AbCdEf" not in entries[0].content
        assert "-".join(("glpat", "AbCdEf1234567890xyzw")) not in entries[0].content
    finally:
        app.state.runtime.cleanup()


# T5-04 (G5): Postgres ioc_cols preserves timestamps / prevents count inflation & DatabaseConfig validates backend/dsn
@pytest.mark.feature("F5")
@pytest.mark.feature("F6")
def test_t5_04_postgres_ioc_idempotency_and_db_config_dialect_validation(
    pillar_workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError):
        DatabaseConfig(backend="sqlite", dsn="postgresql+pg8000://user:pass@pg.internal:5432/soclens")
    with pytest.raises(ValueError):
        DatabaseConfig(backend="postgres", dsn="sqlite:///tmp/mismatch.db")
    with pytest.raises(ValueError):
        DatabaseConfig(backend="mysql", dsn="postgresql://user:pass@pg.internal:5432/soclens")

    # Omitting explicit backend still infers dialect cleanly from DSN
    inferred_pg = DatabaseConfig(dsn="postgresql+pg8000://user:pass@pg.internal:5432/soclens")
    assert inferred_pg.backend == "postgres"
    assert inferred_pg.effective_dialect() == "postgres"

    def pg_responder(sql: str, params: Any) -> tuple[list[str], list[tuple[Any, ...]]] | None:
        low = sql.lower()
        if "from alert_snapshots" in low and "select" in low:
            return ["source", "fetched_at"], [("RF", datetime.fromtimestamp(1767225600.0, tz=UTC))]
        if "from ioc_sightings" in low and "select" in low:
            cols_part = sql[low.index("select") + 6 : low.index("from")].strip()
            col_names = [c.strip().split(".")[-1].split(" as ")[-1].strip() for c in cols_part.split(",")]
            row_map = {
                "id": 42,
                "indicator_norm": "198.51.100.77",
                "event_key": "RF::alert-pg-1",
                "sighting_count": 3,
                "first_seen_at": datetime.fromtimestamp(1767139200.0, tz=UTC),
                "last_seen_at": "2026-01-01T00:00:00Z",
            }
            return col_names, [tuple(row_map.get(c) for c in col_names)]
        return None

    drivers = install_mock_db_drivers(monkeypatch, pg_responder=pg_responder)
    pg_stor = StorageManager(
        DatabaseConfig(backend="postgres", dsn="postgresql+pg8000://soc:pw@pg.internal:5432/soclens")
    )
    try:
        pg_stor.upsert_alerts_snapshot(
            "RF",
            [{"id": "alert-pg-1", "title": "PG IOC", "entities": [{"name": "198.51.100.77", "type": "IpAddress"}]}],
            fetched_at=1767225600.0,
        )
        updates = [
            (sql, params)
            for sql, params in drivers["postgres"].executed_sql
            if "update ioc_sightings" in sql.lower()
        ]
        # Duplicate fetched_at must NOT increment sighting_count from 3 to 4
        assert updates == []

        # Newer fetched_at MUST increment sighting_count from 3 to 4 while preserving first_seen_at
        pg_stor.upsert_alerts_snapshot(
            "RF",
            [{"id": "alert-pg-1", "title": "PG IOC", "entities": [{"name": "198.51.100.77", "type": "IpAddress"}]}],
            fetched_at=1767312000.0,
        )
        updates_after = [
            (sql, params)
            for sql, params in drivers["postgres"].executed_sql
            if "update ioc_sightings" in sql.lower()
        ]
        assert updates_after
        assert any(4 in params for _sql, params in updates_after)
    finally:
        pg_stor.dispose()


# T5-05 (G6): Concurrent SQLite StorageManager initialization, upsert_ioc_sighting, and mark_events_seen_batch
@pytest.mark.feature("F5")
@pytest.mark.feature("F6")
def test_t5_05_concurrent_sqlite_multi_storage_manager_no_race(pillar_workspace: Path) -> None:
    db_file = pillar_workspace / ".soclens_cache" / "concurrent_t5.db"
    errors: list[tuple[int, str, str]] = []
    barrier = threading.Barrier(6)

    def worker(idx: int) -> None:
        s = StorageManager(DatabaseConfig(sqlite_path=db_file))
        try:
            barrier.wait(timeout=5)
            for j in range(5):
                s.upsert_ioc_sighting(
                    indicator="203.0.113.55",
                    indicator_type="ip",
                    source="SplunkES",
                    event_key="shared-ev-1",
                    seen_at=1767225600.0 + j,
                )
                s.mark_events_seen_batch([{"source": "RF", "event_key": f"shared-seen-{j}", "title": "t"}])
        except Exception as exc:
            errors.append((idx, type(exc).__name__, str(exc)))
        finally:
            s.dispose()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert errors == []

    verify_stor = StorageManager(DatabaseConfig(sqlite_path=db_file))
    try:
        sightings = verify_stor.lookup_ioc_sightings("203.0.113.55")
        assert len(sightings) == 1
        assert sightings[0]["sighting_count"] == 30
    finally:
        verify_stor.dispose()


# T5-06 (G7): Web GET /api/ai/chat/stream CSRF & cross-port Sec-Fetch-Site: same-site blocked
@pytest.mark.feature("F13")
def test_t5_06_web_get_stream_and_same_site_csrf_enforced(pillar_workspace: Path) -> None:
    client, app, token = create_web_test_client(pillar_workspace)
    try:
        csrf_hdrs = exchange_web_auth(client, token)
        # Same-site (e.g. different localhost port) must be rejected
        r_samesite = client.post(
            "/api/settings",
            json={"updates": {}},
            headers={**csrf_hdrs, "Sec-Fetch-Site": "same-site"},
        )
        assert r_samesite.status_code == 403

        # Un-CSRF'd GET stream must not execute LLM investigations
        r_get_stream = client.get("/api/ai/chat/stream?prompt=hello")
        assert r_get_stream.status_code in (403, 405)

        # POST without X-SOCLens-Token must be rejected with 403
        r_post_no_csrf = client.post(
            "/api/ai/chat/stream",
            json={"prompt": "hello"},
        )
        assert r_post_no_csrf.status_code == 403
    finally:
        app.state.runtime.cleanup()


# T5-07 (G8): Bundler must not archive external symlink targets outside workspace_dir
@pytest.mark.feature("F3")
@pytest.mark.feature("F4")
def test_t5_07_bundler_blocks_external_symlinks(pillar_workspace: Path, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "docs").mkdir(parents=True)
    (ws / "docs" / "safe.md").write_text("# Safe doc\n", encoding="utf-8")
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("TOP_SECRET_CREDENTIAL", encoding="utf-8")
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "hidden.txt").write_text("SECRET_DIR_FILE", encoding="utf-8")

    (ws / "docs" / "linked_secret.txt").symlink_to(outside)
    (ws / "docs" / "linked_dir").symlink_to(outside_dir)
    out_zip = tmp_path / "bundle.zip"
    create_bundle(workspace_dir=ws, output_path=out_zip)
    with zipfile.ZipFile(out_zip) as zf:
        names = zf.namelist()
        assert "docs/safe.md" in names
        assert "docs/linked_secret.txt" not in names
        assert not any(n.startswith("docs/linked_dir/") for n in names)


# T5-08 (G9): SplunkESPane in TileLeaf at 76 <= w < 96 keeps full width when stacked vertically
@pytest.mark.feature("F11")
def test_t5_08_splunk_es_narrow_tile_uses_full_width_when_stacked(pillar_workspace: Path) -> None:
    app = make_pillar_app(pillar_workspace, initial_tab="tab-splunk-es")

    async def _run() -> None:
        async with app.run_test(size=(170, 44)) as pilot:
            await pilot.pause()
            await press_tile_key(pilot, "alt+t")
            await press_tile_key(pilot, "alt+v")
            await pilot.pause()
            found_es = False
            for lf in app.query(TileLeaf):
                if getattr(lf, "pane_id", None) == "tab-splunk-es":
                    found_es = True
                    es_pane = lf.query_one(SplunkESPane)
                    ws_box = es_pane.query_one("#es-workspace")
                    master = es_pane.query_one("#es-master-pane")
                    detail = es_pane.query_one("#es-detail-pane")
                    assert not ws_box.has_class("split-horizontal")
                    assert getattr(ws_box.styles.layout, "name", "") == "vertical"
                    assert master.region.width >= lf.size.width - 4
                    assert detail.region.width >= lf.size.width - 4
            assert found_es

    asyncio.run(_run())


# T5-09 (G11 + SPL/FTS5 adversarial checks): SPL lexer, FTS5 special chars, env scrub
@pytest.mark.feature("F2")
@pytest.mark.feature("F5")
def test_t5_09_spl_lexer_fts5_and_env_scrubbing(pillar_workspace: Path) -> None:
    assert "SOCLENS_AI_MAX_TOOL_STEPS" not in os.environ
    for bad_spl in (
        "index=security 'foo' | outputlookup evil.csv",
        "index=security ```hidden``` | outputlookup evil.csv",
        "index=security [search index=main] outputlookup evil.csv",
        r'index=security foo="bar\" | outputlookup evil.csv',
        "index=security | COLLECT index=evil",
    ):
        ok, _ = validate_readonly_spl(bad_spl)
        assert ok is False

    stor = StorageManager(DatabaseConfig(sqlite_path=pillar_workspace / ".soclens_cache" / "fts_t5.db"))
    try:
        stor.upsert_learning(title="C++ & Edge:Token", content="host=web-01:8443", category="environment_fact")
        for q in ("C++", "web-01:8443", '"unclosed', "OR", "NOT", "***", "()"):
            stor.search_learnings(q)
    finally:
        stor.dispose()


# T5-10 (G10): Web tear-off mode disables workspace layout persistence so main layout is preserved
@pytest.mark.feature("F14")
def test_t5_10_web_tearoff_disables_layout_persistence(pillar_workspace: Path) -> None:
    app_js = (_REPO_ROOT / "soclens" / "web" / "static" / "app.js").read_text(encoding="utf-8")
    tiling_js = (_REPO_ROOT / "soclens" / "web" / "static" / "tiling.js").read_text(encoding="utf-8")
    assert "persistEnabled: !tearoffTile" in app_js
    assert "this.persistEnabled === false" in tiling_js

    node_bin = shutil.which("node")
    if node_bin:
        probe_js = r"""
const fs = require("fs");
const vm = require("vm");
const calls = [];
const sandbox = {
  window: {
    SOCLensAPI: {
      isAuthenticated: () => true,
      apiFetch: (path, opts) => { calls.push({ path, opts }); return Promise.resolve({}); },
    },
  },
  document: { createElement: () => ({ className: "", style: {}, dataset: {}, appendChild: () => {}, addEventListener: () => {} }) },
  requestAnimationFrame: () => {},
  setTimeout: (fn) => { fn(); return 1; },
  clearTimeout: () => {},
  SOCLensTiles: {},
};
sandbox.window.SOCLensTiling = undefined;
vm.runInNewContext(fs.readFileSync(process.argv[1], "utf-8"), sandbox);
const reg = new Map([["research", { title: "Research" }], ["logs", { title: "Logs" }]]);
const tearoffMgr = new sandbox.window.SOCLensTiling.BSPTilingManager(null, reg, { persistEnabled: false });
tearoffMgr.workspaces["1"] = { type: "leaf", id: "tearoff-leaf", tabs: ["logs"], activeTab: "logs" };
tearoffMgr.focusedLeafId = "tearoff-leaf";
tearoffMgr.switchWorkspace("2");
tearoffMgr.toggleZoom();
if (calls.length !== 0) {
  throw new Error("Expected 0 persist calls in tearoff mode, got " + calls.length);
}
const mainMgr = new sandbox.window.SOCLensTiling.BSPTilingManager(null, reg, { persistEnabled: true });
mainMgr.switchWorkspace("2");
if (calls.length !== 1 || calls[0].path !== "/api/workspace/layout") {
  throw new Error("Expected 1 persist call when persistEnabled=true");
}
"""
        proc = subprocess.run(
            [node_bin, "-e", probe_js, str(_REPO_ROOT / "soclens" / "web" / "static" / "tiling.js")],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"Node tearoff probe failed: {proc.stderr}\n{proc.stdout}"
