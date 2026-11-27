"""Comprehensive unit & integration tests for soclens/storage.py and M2 store adapters."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from soclens.agent_audit import AuditEntry, AuditLogStore
from soclens.agent_orchestrator import InvestigationResult
from soclens.agent_policy import AIPolicyStore
from soclens.alert_cache import AlertCacheStore
from soclens.event_tracker import EventAIStore, UniqueEvent
from soclens.settings import clear_session_overrides, invalidate_settings_cache
from soclens.storage import (
    DatabaseConfig,
    SOCLearningStore,
    StorageManager,
    test_db_connection,
)
from tests.db_test_helpers import install_mock_db_drivers, make_sample_ca_cert_pem


@pytest.fixture
def isolated_db_ws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SOCLENS_HOME", str(ws))
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(tmp_path / "settings.json"))
    for key in (
        "SOCLENS_DB_BACKEND",
        "SOCLENS_DB_DSN",
        "DATABASE_URL",
        "SOCLENS_DB_PASSWORD",
        "SOCLENS_WORKSTATION_ID",
        "SOCLENS_PROFILE",
        "SOCLENS_ANALYST_ID",
    ):
        monkeypatch.delenv(key, raising=False)
    clear_session_overrides()
    invalidate_settings_cache()
    return ws


def test_default_sqlite_wal_busy_timeout_and_repr_masking(isolated_db_ws: Path) -> None:
    cfg = DatabaseConfig(
        backend="postgres",
        host="db.soc.internal",
        port=5432,
        database="soclens",
        username="soc_user",
        password="SuperSecretDbPassword99",
    )
    rep = repr(cfg)
    assert "SuperSecretDbPassword99" not in rep
    assert "db.soc.internal" in rep

    sqlite_cfg = DatabaseConfig(sqlite_path=isolated_db_ws / ".soclens_cache" / "soclens.db")
    assert isinstance(sqlite_cfg.sqlite_path, Path)
    assert sqlite_cfg.retention_days == 90

    storage = StorageManager(sqlite_cfg)
    storage.ensure_schema()
    assert sqlite_cfg.sqlite_path.is_file()

    with storage.get_engine().connect() as conn:
        journal = str(conn.execute(text("PRAGMA journal_mode")).scalar_one()).lower()
        busy = int(conn.execute(text("PRAGMA busy_timeout")).scalar_one())
        fk = int(conn.execute(text("PRAGMA foreign_keys")).scalar_one())
    assert journal == "wal"
    assert busy >= 5000
    assert fk == 1

    # Both module-level test_db_connection, static StorageManager.test_connection,
    # and instance storage.test_connection() must work.
    res_mod = test_db_connection(sqlite_cfg)
    res_cls = StorageManager.test_connection(sqlite_cfg)
    res_inst = storage.test_connection()
    assert res_mod["ok"] is True and res_mod["dialect"] == "sqlite"
    assert res_cls["ok"] is True and res_cls["dialect"] == "sqlite"
    assert res_inst["ok"] is True and res_inst["dialect"] == "sqlite"


def test_sqlite_fts5_search_and_adversarial_queries(isolated_db_ws: Path) -> None:
    db_path = isolated_db_ws / ".soclens_cache" / "soclens.db"
    storage = StorageManager(DatabaseConfig(sqlite_path=db_path))
    storage.ensure_schema()

    with sqlite3.connect(db_path) as conn:
        sqls = [
            str(r[0] or "").lower()
            for r in conn.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
        ]
    assert any("alerts_history_fts" in s and "fts5" in s for s in sqls)
    assert any("soc_learnings_fts" in s and "fts5" in s for s in sqls)

    storage.upsert_alerts_snapshot(
        "es_notables_24h",
        [
            {
                "finding_id": "es-fts-1",
                "rule_name": "Kerberoasting TGS Anomaly CVE-2024-3094",
                "src_ip": "10.20.30.40",
                "summary": r"C:\Windows\System32\cmd.exe invoked from Office",
            },
            {
                "finding_id": "es-fts-2",
                "rule_name": "Routine Healthcheck",
                "src_ip": "10.20.30.99",
            },
        ],
    )
    storage.upsert_learning(
        title="Windows Cmd Path",
        content=r"Monitor C:\Windows\System32\cmd.exe spawning from winword.exe.",
        category="environment_fact",
        source="manual_learn",
        status="active",
    )

    assert storage.search_alerts_history("") == []
    assert storage.search_alerts_history("   \n\t ") == []
    assert storage.search_learnings("   ") == []

    hits = storage.search_alerts_history("Kerberoasting", limit=10)
    assert len(hits) == 1
    assert hits[0]["alert_id"] == "es-fts-1"

    for nasty in (
        'OR "1=1" -- ; DROP TABLE alerts;',
        "CVE-2024-3094 AND (foo OR *)",
        r"C:\Windows\System32\cmd.exe",
        '"""unbalanced((brackets',
    ):
        assert isinstance(storage.search_alerts_history(nasty, limit=10), list)
        assert isinstance(storage.search_learnings(nasty, limit=10), list)

    assert storage.search_alerts_history("CVE-2024-3094", limit=10)
    assert storage.search_learnings("cmd.exe", limit=10)


def test_sqlite_concurrent_threads_and_ioc_extraction(isolated_db_ws: Path) -> None:
    db_path = isolated_db_ws / ".soclens_cache" / "soclens.db"
    storage = StorageManager(DatabaseConfig(sqlite_path=db_path))
    storage.ensure_schema()

    errors: list[BaseException] = []

    def _worker(tid: int) -> None:
        try:
            for idx in range(3):
                ip = f"198.51.100.{tid * 10 + idx + 1}"
                storage.upsert_alerts_snapshot(
                    "rf_alerts_24h",
                    [{"id": f"rf-{tid}-{idx}", "title": f"Beacon to {ip}", "src_ip": ip}],
                )
                storage.search_alerts_history(ip, limit=5)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15.0)

    assert not errors
    assert storage.lookup_ioc_sightings("198.51.100.1")

    # Case-insensitive IOC/CVE sightings
    storage.upsert_ioc_sighting(
        indicator="CVE-2024-3094",
        indicator_type="cve",
        source="rf_alerts_24h",
        event_key="rf_alert:default:rf-1",
    )
    storage.upsert_ioc_sighting(
        indicator="cve-2024-3094",
        indicator_type="cve",
        source="es_notables_24h",
        event_key="splunk_es:default:es-1",
    )
    rows = storage.lookup_ioc_sightings("CVE-2024-3094")
    assert len(rows) == 2


def test_legacy_migration_idempotent_and_corrupt_survival(isolated_db_ws: Path) -> None:
    cache_dir = isolated_db_ws / ".soclens_cache"
    alerts_dir = cache_dir / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)

    (alerts_dir / "rf_alerts_24h.json").write_text(
        json.dumps(
            {
                "source": "rf_alerts_24h",
                "fetched_at": time.time() - 60,
                "items": [
                    {
                        "id": "rf-mig-1",
                        "title": "Migrated C2 203.0.113.42 CVE-2024-3094",
                        "api_key": "sk-proj-secretvaluemustredact1234",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (alerts_dir / "s1_threats_24h.json").write_text("{corrupt json", encoding="utf-8")
    (alerts_dir / "es_notables_24h.json").write_text("", encoding="utf-8")

    (cache_dir / "event_ai_panels.json").write_text(
        json.dumps(
            {
                "version": 1,
                "events": {
                    "rf_alert:default:rf-mig-1": {
                        "event": {
                            "event_key": "rf_alert:default:rf-mig-1",
                            "source_kind": "rf_alert",
                            "native_id": "rf-mig-1",
                            "title": "Migrated C2",
                        },
                        "panels": [
                            {
                                "entry_id": "panel-mig-1",
                                "run_id": "run-mig-1",
                                "timestamp": "2026-11-26T12:00:00Z",
                                "mode": "ask_only",
                                "provider": "ollama",
                                "model": "llama3.2",
                                "question": "Check",
                                "answer_markdown": "Authorization: Bearer raw-mig-secret-999",
                                "status": "completed",
                            }
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (cache_dir / "ai_policy.json").write_text(
        json.dumps({"max_tool_steps": 27, "disabled_tools": ["osint_enrich_target"]}),
        encoding="utf-8",
    )
    good_audit = json.dumps(
        {
            "entry_id": "aud-mig-1",
            "timestamp": "2026-11-26T12:00:00Z",
            "run_id": "run-mig-1",
            "event_key": "rf_alert:default:rf-mig-1",
            "provider": "ollama",
            "mode": "ask_only",
            "event_type": "decision",
            "reason": "Bearer audit-mig-secret-999",
        }
    )
    bad_type_audit = json.dumps(
        {
            "entry_id": "aud-bad-type",
            "timestamp": "2026-11-26T12:00:00Z",
            "event_type": "invalid_event_type",
        }
    )
    (cache_dir / "ai_audit.jsonl").write_text(
        f"{good_audit}\n{{bad json line\n{bad_type_audit}\n",
        encoding="utf-8",
    )

    db_path = cache_dir / "soclens.db"
    storage = StorageManager(DatabaseConfig(sqlite_path=db_path))
    storage.ensure_schema()

    c1 = storage.migrate_legacy_files(cache_dir)
    assert c1["alerts_sources"] == 1
    assert c1["panels"] == 1
    assert c1["policies"] == 1
    assert c1["audits"] == 1

    # Idempotent second pass
    storage.migrate_legacy_files(cache_dir)
    assert len(storage.get_event_panels("rf_alert:default:rf-mig-1")) == 1
    assert len(storage.query_audit_entries(event_key="rf_alert:default:rf-mig-1")) == 1
    assert storage.lookup_ioc_sightings("203.0.113.42")
    assert storage.lookup_ioc_sightings("cve-2024-3094")
    assert AIPolicyStore(storage=storage).load().max_tool_steps == 27

    storage.get_engine().dispose()
    raw_bytes = db_path.read_bytes().decode("latin-1", errors="ignore")
    for leaked in ("sk-proj-secretvaluemustredact1234", "raw-mig-secret-999", "audit-mig-secret-999"):
        assert leaked not in raw_bytes


def test_retention_boundaries_and_protected_learnings(isolated_db_ws: Path) -> None:
    storage = StorageManager(DatabaseConfig(sqlite_path=isolated_db_ws / ".soclens_cache" / "soclens.db"))
    storage.ensure_schema()
    now = datetime.now(UTC)

    ts_89d = now - timedelta(days=89)
    ts_91d = now - timedelta(days=91)
    storage.upsert_alerts_snapshot(
        "es_notables_24h",
        [{"finding_id": "es-89d", "rule_name": "Keep 89d", "time": ts_89d.strftime("%Y-%m-%dT%H:%M:%SZ")}],
        fetched_at=ts_89d.timestamp(),
    )
    storage.upsert_alerts_snapshot(
        "es_notables_24h",
        [{"finding_id": "es-91d", "rule_name": "Prune 91d", "time": ts_91d.strftime("%Y-%m-%dT%H:%M:%SZ")}],
        fetched_at=ts_91d.timestamp(),
    )
    base_entry = storage.upsert_learning(
        title="Base Seed Fact",
        content="Must never be pruned",
        source="base_seed",
        status="active",
        created_at=ts_91d.timestamp(),
        updated_at=ts_91d.timestamp(),
    )
    pinned_entry = storage.upsert_learning(
        title="Pinned Fact",
        content="Also must never be pruned",
        source="manual_learn",
        status="active",
        pinned=True,
        created_at=ts_91d.timestamp(),
        updated_at=ts_91d.timestamp(),
    )

    storage.prune_expired(retention_days=90)
    assert storage.search_alerts_history("Keep 89d")
    assert not storage.search_alerts_history("Prune 91d")
    assert storage.get_learning(base_entry["id"]) is not None
    assert storage.get_learning(pinned_entry["id"]) is not None

    ts_23h = now - timedelta(hours=23)
    ts_25h = now - timedelta(hours=25)
    storage.upsert_alerts_snapshot(
        "es_notables_24h",
        [{"finding_id": "es-23h", "rule_name": "Keep 23h", "time": ts_23h.strftime("%Y-%m-%dT%H:%M:%SZ")}],
        fetched_at=ts_23h.timestamp(),
    )
    storage.upsert_alerts_snapshot(
        "es_notables_24h",
        [{"finding_id": "es-25h", "rule_name": "Prune 25h", "time": ts_25h.strftime("%Y-%m-%dT%H:%M:%SZ")}],
        fetched_at=ts_25h.timestamp(),
    )
    storage.prune_expired(retention_days=1)
    assert storage.search_alerts_history("Keep 23h")
    assert not storage.search_alerts_history("Prune 25h")

    # retention_days=0 is a safe no-op
    res_zero = storage.prune_expired(retention_days=0)
    assert res_zero["alerts_history"] == 0
    assert storage.search_alerts_history("Keep 23h")


def test_postgres_mysql_dialects_tls_pooling_and_error_sanitization(
    isolated_db_ws: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drivers = install_mock_db_drivers(monkeypatch)
    ca_file = isolated_db_ws / "ca.pem"
    ca_file.write_text(make_sample_ca_cert_pem(), encoding="utf-8")

    pw = "SuperSecretPw42!"
    pg_cfg = DatabaseConfig(
        backend="postgres",
        dsn=f"postgresql+pg8000://soc:{pw}@pg.internal.example:5432/soclens",
        ssl_mode="verify-full",
        ssl_ca=str(ca_file),
        pool_size=3,
        max_overflow=2,
    )
    pg_status = StorageManager.test_connection(pg_cfg)
    assert pg_status["ok"] is True
    assert pg_status["dialect"] == "postgres"
    assert "ssl_context" in drivers["postgres"].connect_calls[-1]

    pg_stor = StorageManager(pg_cfg)
    pg_stor.ensure_schema()
    before_pg = len(drivers["postgres"].executed_sql)
    pg_stor.search_alerts_history("100%_test'quote", limit=5)
    pg_sql = "\n".join(s for s, _ in drivers["postgres"].executed_sql[before_pg:]).lower()
    assert "tsvector" in pg_sql and "ilike" in pg_sql
    assert "100%_test'quote" not in pg_sql

    mysql_cfg = DatabaseConfig(
        backend="mysql",
        dsn=f"mysql+pymysql://soc:{pw}@mysql.internal.example:3306/soclens",
        ssl_mode="verify-ca",
        ssl_ca=str(ca_file),
    )
    mysql_status = StorageManager.test_connection(mysql_cfg)
    assert mysql_status["ok"] is True
    assert mysql_status["dialect"] == "mysql"
    assert drivers["mysql"].connect_calls[-1]["ssl"]["ca"] == str(ca_file)

    mysql_stor = StorageManager(mysql_cfg)
    mysql_stor.ensure_schema()
    all_mysql = "\n".join(s for s, _ in drivers["mysql"].executed_sql).lower()
    assert "fulltext" in all_mysql
    before_my = len(drivers["mysql"].executed_sql)
    mysql_stor.search_alerts_history("PowerShell", limit=5)
    my_sql = "\n".join(s for s, _ in drivers["mysql"].executed_sql[before_my:]).lower()
    assert "match(" in my_sql or "match (" in my_sql

    # Error sanitization never leaks password
    drivers["postgres"].fail_on_connect = drivers["postgres"].OperationalError(
        f"password authentication failed for {pw}"
    )
    err_res = StorageManager.test_connection(pg_cfg)
    assert err_res["ok"] is False
    assert pw not in str(err_res["error"])
    drivers["postgres"].fail_on_connect = None

    with pytest.raises(ValueError):
        DatabaseConfig(backend="oracle", dsn=f"oracle://u:{pw}@host/orcl")
    with pytest.raises(ValueError):
        DatabaseConfig(backend="custom", dsn="")


def test_store_adapters_scoping_and_learning_store_revisions(isolated_db_ws: Path) -> None:
    db_path = isolated_db_ws / ".soclens_cache" / "soclens.db"
    stor_a = StorageManager(
        DatabaseConfig(sqlite_path=db_path, workstation_id="ws-a", profile_name="p1", analyst_id="alice")
    )
    stor_b = StorageManager(
        DatabaseConfig(sqlite_path=db_path, workstation_id="ws-b", profile_name="p2", analyst_id="bob")
    )
    stor_a.ensure_schema()

    # Scoped policy & workspace layout
    pol_a = AIPolicyStore(storage=stor_a)
    pol_b = AIPolicyStore(storage=stor_b)
    pol_a.update(max_tool_steps=11)
    pol_b.update(max_tool_steps=42)
    assert pol_a.load().max_tool_steps == 11
    assert pol_b.load().max_tool_steps == 42

    stor_a.save_workspace_layout(mode="tiling", state={"active_workspace": 3})
    stor_b.save_workspace_layout(mode="tabbed", state={"active_workspace": 1})
    assert stor_a.load_workspace_layout()["mode"] == "tiling"
    assert stor_b.load_workspace_layout()["mode"] == "tabbed"

    # AlertCacheStore with storage
    ac = AlertCacheStore(cache_dir=isolated_db_ws / "alerts_cache", load_on_init=False, storage=stor_a)
    ac.put("es_notables_24h", [{"finding_id": "es-adp-1", "rule_name": "Shared Alert"}])
    assert stor_b.search_alerts_history("Shared Alert")
    ac_reloaded = AlertCacheStore(cache_dir=isolated_db_ws / "empty_alerts", load_on_init=True, storage=stor_b)
    assert ac_reloaded.get("es_notables_24h") is not None

    # EventAIStore with storage
    ev = UniqueEvent(
        event_key="splunk_es:default:es-adp-1",
        source_kind="splunk_es",
        native_id="es-adp-1",
        title="Shared Alert",
        severity="high",
    )
    ev_a = EventAIStore(storage=stor_a)
    ev_a.upsert_event(ev)
    ev_a.attach_ai_response(
        ev,
        InvestigationResult(
            run_id="r1",
            event_key=ev.event_key,
            mode="ask_only",
            provider="ollama",
            model="llama3.2",
            question="Summary",
            answer_markdown="Confirmed clean.",
            tool_calls=[],
            blocked_actions=[],
            status="completed",
        ),
    )
    ev_b = EventAIStore(storage=stor_b)
    assert ev_b.has_investigation(ev.event_key) is True

    # AuditLogStore stamps analyst_id & workstation_id
    aud_a = AuditLogStore(storage=stor_a)
    saved_aud = aud_a.append(
        AuditEntry(
            entry_id="aud-sc-1",
            timestamp="2026-11-26T12:00:00Z",
            run_id="run-sc-1",
            event_key=ev.event_key,
            provider="ollama",
            mode="ask_only",
            event_type="decision",
            reason="Tagged audit check",
        )
    )
    assert saved_aud.analyst_id == "alice"
    assert saved_aud.workstation_id == "ws-a"
    queried_b = stor_b.query_audit_entries(event_key=ev.event_key)
    assert queried_b and queried_b[0].analyst_id == "alice"

    # SOCLearningStore revisions
    lstore = SOCLearningStore(stor_a)
    created = lstore.upsert(
        title="Revision Test",
        content="Initial content",
        category="environment_fact",
        source="manual_learn",
        status="active",
    )
    lstore.record_revision(
        learning_id=created["id"],
        action="create",
        actor="alice",
        new_content="Initial content",
        new_status="active",
        snapshot=created,
    )
    revs = lstore.get_revisions(created["id"])
    assert len(revs) == 1 and revs[0]["action"] == "create"


def test_event_panels_preserve_insertion_order_within_same_second(isolated_db_ws: Path) -> None:
    mgr = StorageManager(
        DatabaseConfig(sqlite_path=isolated_db_ws / ".soclens_cache" / "soclens.db")
    )
    mgr.ensure_schema()
    ev = {
        "event_key": "rf_alert::order-1",
        "source_kind": "rf_alert",
        "native_id": "order-1",
        "scope": "default",
        "title": "Same-second panel ordering",
        "severity": "high",
    }
    ts = "2026-11-26T23:59:59Z"
    mgr.add_event_panel(
        "rf_alert::order-1",
        {
            "entry_id": "zzzz-first",
            "run_id": "run-1",
            "timestamp": ts,
            "mode": "ask_only",
            "provider": "ollama",
            "model": "m",
            "question": "First?",
            "answer_markdown": "First answer",
        },
        event_dict=ev,
    )
    mgr.add_event_panel(
        "rf_alert::order-1",
        {
            "entry_id": "aaaa-second",
            "run_id": "run-2",
            "timestamp": ts,
            "mode": "full_investigation",
            "provider": "ollama",
            "model": "m",
            "question": "Second?",
            "answer_markdown": "Second answer",
        },
        event_dict=ev,
    )
    panels = mgr.get_event_panels("rf_alert::order-1")
    assert [p["entry_id"] for p in panels] == ["zzzz-first", "aaaa-second"]
    assert [p["mode"] for p in panels] == ["ask_only", "full_investigation"]
    mgr.dispose()


def test_db_and_wal_never_persist_dsn_or_vault_secrets_and_alert_cache_redacts(
    isolated_db_ws: Path,
) -> None:
    db_path = isolated_db_ws / ".soclens_cache" / "soclens.db"
    wal_path = Path(f"{db_path}-wal")
    mgr = StorageManager(DatabaseConfig(sqlite_path=db_path))
    mgr.ensure_schema()

    pg_pw = "DsnPgSecretPass88!"
    my_pw = "DsnMySqlSecretPass77!"
    vault_uri = "vault://secret/data/soclens/prod#db_password"
    hvs_tok = "hvs.CAESIJTestVaultServiceToken99999"

    mgr.upsert_alerts_snapshot(
        "es_notables_24h",
        [
            {
                "finding_id": "es-sec-1",
                "rule_name": "DB Credential Leak Check",
                "db_dsn": f"postgresql+pg8000://soc_user:{pg_pw}@pg.corp.example:5432/soclens",
                "vault_ref": vault_uri,
                "summary": (
                    f"mysql+pymysql://my_user:{my_pw}@mysql.corp.example:3306/soclens "
                    f"and vault:v1:{hvs_tok}"
                ),
            }
        ],
    )
    mgr.add_event_panel(
        "splunk_es:default:es-sec-1",
        {
            "entry_id": "panel-sec-1",
            "run_id": "run-sec-1",
            "timestamp": "2026-11-27T00:00:00Z",
            "mode": "ask_only",
            "provider": "ollama",
            "model": "llama3.2",
            "question": f"Check {vault_uri}",
            "answer_markdown": (
                f"postgresql+pg8000://soc_user:{pg_pw}@pg.corp.example:5432/soclens "
                f"token={hvs_tok}"
            ),
            "status": "completed",
        },
        event_dict={
            "event_key": "splunk_es:default:es-sec-1",
            "source_kind": "splunk_es",
            "native_id": "es-sec-1",
            "title": "Secret Leak Probe",
            "metadata": {"db_dsn": f"mysql+pymysql://u:{my_pw}@h:3306/db"},
        },
    )
    AuditLogStore(storage=mgr).append(
        AuditEntry(
            entry_id="aud-sec-1",
            timestamp="2026-11-27T00:00:00Z",
            run_id="run-sec-1",
            event_key="splunk_es:default:es-sec-1",
            provider="ollama",
            mode="ask_only",
            event_type="decision",
            reason=f"Saw {vault_uri} and {hvs_tok}",
            payload={
                "db_dsn": f"postgresql+pg8000://soc_user:{pg_pw}@pg.corp.example:5432/soclens",
                "vault_ref": vault_uri,
            },
        )
    )
    mgr.upsert_learning(
        title="DB DSN Hygiene",
        content=(
            f"Never store postgresql+pg8000://soc_user:{pg_pw}@pg.corp.example:5432/soclens "
            f"or mysql+pymysql://my_user:{my_pw}@mysql.corp.example:3306/soclens "
            f"or {vault_uri} or {hvs_tok}"
        ),
        category="environment_fact",
        source="manual_learn",
        status="active",
    )

    for probe_path in (db_path, wal_path):
        if probe_path.is_file():
            raw = probe_path.read_bytes().decode("latin-1", errors="ignore")
            for needle in (pg_pw, my_pw, "secret/data/soclens/prod", hvs_tok):
                assert needle not in raw, f"Leaked {needle!r} in {probe_path.name}"

    mgr.dispose()
    raw_post = db_path.read_bytes().decode("latin-1", errors="ignore")
    for needle in (pg_pw, my_pw, "secret/data/soclens/prod", hvs_tok):
        assert needle not in raw_post

    # AlertCacheStore.update_cached_item() must also redact before writing JSON to disk
    ac_dir = isolated_db_ws / "alerts_cache_sec"
    ac = AlertCacheStore(cache_dir=ac_dir, load_on_init=False)
    ac.put("rf_playbook_24h", [{"playbook_alert_id": "pb-1", "title": "Initial"}])
    updated = ac.update_cached_item(
        "rf_playbook_24h",
        "pb-1",
        item_updates={
            "db_dsn": f"postgresql+pg8000://soc_user:{pg_pw}@pg.corp.example:5432/soclens",
            "vault_ref": vault_uri,
        },
        detail={"secret_note": f"mysql+pymysql://my_user:{my_pw}@mysql.corp.example:3306/soclens {hvs_tok}"},
    )
    assert updated is True
    disk_json = (ac_dir / "rf_playbook_24h.json").read_text(encoding="utf-8")
    for needle in (pg_pw, my_pw, "secret/data/soclens/prod", hvs_tok):
        assert needle not in disk_json


def test_mysql_boolean_mode_cve_tokenization_and_snapshot_ioc_and_audit_idempotency(
    isolated_db_ws: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drivers = install_mock_db_drivers(monkeypatch)
    mysql_cfg = DatabaseConfig(
        backend="mysql",
        dsn="mysql+pymysql://soc:pw@mysql.internal.example:3306/soclens",
    )
    mysql_stor = StorageManager(mysql_cfg)
    mysql_stor.ensure_schema()

    before = len(drivers["mysql"].executed_sql)
    mysql_stor.search_alerts_history("CVE-2024-3094", limit=5)
    mysql_stor.search_learnings("CVE-2024-3094", limit=5)
    queries = drivers["mysql"].executed_sql[before:]
    mq_params = [str(p.get("mq", "")) for _s, p in queries if isinstance(p, dict) and "mq" in p]
    assert len(mq_params) == 2
    for mq in mq_params:
        assert mq == "+CVE* +2024* +3094*"
        assert "-" not in mq
    mysql_stor.dispose()

    # Batch audit migration idempotency + snapshot IOC non-inflation on same fetched_at
    cache_dir = isolated_db_ws / ".soclens_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    audit_lines = [
        json.dumps(
            {
                "entry_id": f"aud-batch-{i}",
                "timestamp": "2026-11-27T00:00:00Z",
                "run_id": "run-batch",
                "event_key": "es::1",
                "provider": "ollama",
                "mode": "ask_only",
                "event_type": "decision",
                "reason": f"Batch entry {i}",
            }
        )
        for i in range(5)
    ]
    (cache_dir / "ai_audit.jsonl").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    stor = StorageManager(DatabaseConfig(sqlite_path=cache_dir / "soclens.db"))
    stor.ensure_schema()
    m1 = stor.migrate_legacy_files(cache_dir)
    assert m1["audits"] == 5
    m2 = stor.migrate_legacy_files(cache_dir)
    assert m2["audits"] == 0
    assert len(stor.query_audit_entries(run_id="run-batch", limit=20)) == 5

    fixed_ts = time.time() - 30.0
    items = [{"finding_id": "es-idem-1", "rule_name": "IOC 198.51.100.77 CVE-2024-3094"}]
    stor.upsert_alerts_snapshot("es_notables_24h", items, fetched_at=fixed_ts)
    stor.upsert_alerts_snapshot("es_notables_24h", items, fetched_at=fixed_ts)
    s_same = stor.lookup_ioc_sightings("198.51.100.77")
    assert len(s_same) == 1
    assert s_same[0]["sighting_count"] == 1

    stor.upsert_alerts_snapshot("es_notables_24h", items, fetched_at=fixed_ts + 60.0)
    s_newer = stor.lookup_ioc_sightings("198.51.100.77")
    assert len(s_newer) == 1
    assert s_newer[0]["sighting_count"] == 2
    stor.dispose()
