"""Process-scoped runtime state container for the SOCLens Web backend."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from soclens import __version__
from soclens.agent_audit import AuditLogStore
from soclens.agent_learning import SOCLearningManager
from soclens.agent_orchestrator import SocAgentOrchestrator
from soclens.agent_policy import AIPolicyConfig, AIPolicyStore
from soclens.agent_tools import ReadOnlyToolRegistry, build_default_readonly_registry
from soclens.alert_cache import AlertCacheStore
from soclens.api_access import ApiAccessRegistry
from soclens.client import RecordedFutureClient
from soclens.config import (
    ConfigurationError,
    get_database_config,
    get_local_llm_config,
    get_rf_token,
    get_rf_verify_ssl,
    get_sentinelone_config,
    get_splunk_config,
    suppress_insecure_ssl_warnings,
)
from soclens.event_tracker import (
    BackgroundTriageQueue,
    EventAIStore,
    InvestigationResult,
    UniqueEvent,
)
from soclens.llm import LocalLLMClient
from soclens.osint import OSINTClient
from soclens.sentinelone import SentinelOneClient
from soclens.settings import (
    clear_session_overrides,
    clear_unlocked_keys,
    is_settings_locked,
)
from soclens.splunk import SplunkClient
from soclens.splunk_es import SPLUNK_ES_APP, SplunkESClient
from soclens.storage import DatabaseConfig, StorageManager, _sanitize_db_error
from soclens.tui.logging_bridge import AppLogStore, LogEntry, TuiLogHandler
from soclens.web.security import WebAuthManager, redact_web_payload
from soclens.web.sse import SSEEventBus

logger = logging.getLogger("soclens.web")


def _get_session_override_obj(session_state: Any, key: str) -> Any:
    if session_state is None:
        return None
    if isinstance(session_state, dict):
        return session_state.get(key)
    return getattr(session_state, key, None)


class WebRuntimeState:
    """Thread-safe runtime container mirroring ``SocLensApp`` backend stores for ASGI."""

    def __init__(
        self,
        *,
        workspace_dir: Path | str | None = None,
        admin_enabled: bool = False,
        bootstrap_token: str | None = None,
        dry_run: bool = False,
        session_state: Any = None,
    ) -> None:
        self.workspace_dir = (
            Path(workspace_dir).expanduser().resolve()
            if workspace_dir is not None
            else Path.cwd().resolve()
        )
        self.admin_enabled = bool(admin_enabled)
        self.dry_run = bool(dry_run)
        self.session_state = session_state
        self.auth_manager = WebAuthManager(bootstrap_token=bootstrap_token)
        self.sse_bus = SSEEventBus()
        self.shutdown_event = threading.Event()
        self.server_ref: Any = None
        self._lock = threading.RLock()
        self._verify_ssl_override: bool | str | None = None
        self._cleaned_up = False

        self.rf_client: RecordedFutureClient | None = _get_session_override_obj(
            session_state, "rf_client"
        )
        self.s1_client: SentinelOneClient | None = _get_session_override_obj(
            session_state, "s1_client"
        )
        self.splunk_client: SplunkClient | None = _get_session_override_obj(
            session_state, "splunk_client"
        )
        self.splunk_es_client: SplunkESClient | None = _get_session_override_obj(
            session_state, "splunk_es_client"
        )
        self.osint_client: OSINTClient | None = _get_session_override_obj(
            session_state, "osint_client"
        )
        self.llm_client: LocalLLMClient | None = _get_session_override_obj(
            session_state, "llm_client"
        )

        ai_cache_root = self.workspace_dir / ".soclens_cache"
        self.storage_error: str | None = None
        injected_storage = _get_session_override_obj(session_state, "storage")
        if isinstance(injected_storage, StorageManager):
            self.storage = injected_storage
        else:
            db_cfg: DatabaseConfig | None = None
            try:
                db_cfg = get_database_config(workspace_dir=self.workspace_dir)
                self.storage = StorageManager(db_cfg)
            except Exception as exc:
                self.storage_error = str(redact_web_payload(_sanitize_db_error(exc)))
                logger.warning("Database config warning: %s", self.storage_error)
                self.storage = StorageManager(
                    DatabaseConfig(sqlite_path=ai_cache_root / "soclens.db")
                )
            else:
                db_existed_before = (
                    db_cfg.effective_dialect() == "sqlite"
                    and db_cfg.sqlite_path is not None
                    and str(db_cfg.sqlite_path) != ":memory:"
                    and Path(db_cfg.sqlite_path).is_file()
                )
                has_cache_dir = ai_cache_root.is_dir()
                try:
                    self.storage.ensure_schema()
                    migrated_any = False
                    if has_cache_dir:
                        mig_counts = self.storage.migrate_legacy_files(ai_cache_root)
                        migrated_any = any(v > 0 for v in mig_counts.values())
                    if db_existed_before or migrated_any or db_cfg.effective_dialect() != "sqlite":
                        self.storage.prune_expired(retention_days=db_cfg.retention_days)
                except Exception as exc:
                    self.storage_error = str(
                        redact_web_payload(_sanitize_db_error(exc, db_cfg))
                    )
                    logger.warning("Storage initialization warning: %s", self.storage_error)

        active_storage: StorageManager | None = None if self.storage_error is not None else self.storage

        injected_alert_cache = _get_session_override_obj(session_state, "alert_cache")
        if isinstance(injected_alert_cache, AlertCacheStore):
            self.alert_cache = injected_alert_cache
        else:
            self.alert_cache = AlertCacheStore(
                cache_dir=ai_cache_root / "alerts",
                load_on_init=False,
                storage=active_storage,
            )
            try:
                self.alert_cache.load_from_disk_sources()
            except Exception:
                pass

        self.api_access = ApiAccessRegistry(state_path=ai_cache_root / "api_access.json")
        self.ai_policy_store = AIPolicyStore(
            path=ai_cache_root / "ai_policy.json",
            storage=active_storage,
        )
        self.ai_audit_store = AuditLogStore(
            path=ai_cache_root / "ai_audit.jsonl",
            storage=active_storage,
        )
        self.event_ai_store = EventAIStore(
            path=ai_cache_root / "event_ai_panels.json",
            storage=active_storage,
        )

        self._ai_kill_event = threading.Event()
        try:
            initial_policy = self.ai_policy_store.load()
        except Exception as exc:
            self.storage_error = self.storage_error or str(
                redact_web_payload(_sanitize_db_error(exc, self.storage.config))
            )
            self.ai_policy_store.rebind_storage(None)
            try:
                initial_policy = self.ai_policy_store.load()
            except Exception:
                initial_policy = AIPolicyConfig()
        if initial_policy.ai_kill_switch_active:
            if initial_policy.kill_switch_persist_across_restarts:
                self._ai_kill_event.set()
            else:
                try:
                    self.ai_policy_store.update(ai_kill_switch_active=False)
                except Exception:
                    pass

        injected_lm = _get_session_override_obj(session_state, "learning_manager")
        if isinstance(injected_lm, SOCLearningManager):
            self.learning_manager = injected_lm
        else:
            self.learning_manager = SOCLearningManager(
                storage=lambda: self.storage,
                workspace_dir=self.workspace_dir,
                policy_store=self.ai_policy_store,
                audit_store=self.ai_audit_store,
            )
        if self.storage_error is None:
            try:
                self.learning_manager.load_base_knowledge(self.workspace_dir)
            except Exception:
                pass

        self.ai_tool_registry: ReadOnlyToolRegistry = build_default_readonly_registry(
            rf_client=self.get_rf_client,
            s1_client=self.get_s1_client,
            splunk_client=self.get_splunk_client,
            splunk_es_client=self.get_splunk_es_client,
            osint_client=self.get_osint_client,
            storage=lambda: self.storage,
            learning_manager=lambda: self.learning_manager,
        )

        injected_orch = _get_session_override_obj(session_state, "ai_orchestrator")
        if isinstance(injected_orch, SocAgentOrchestrator):
            self.ai_orchestrator = injected_orch
        else:
            llm_factory = _get_session_override_obj(session_state, "llm_client_factory")
            self.ai_orchestrator = SocAgentOrchestrator(
                registry=self.ai_tool_registry,
                policy_store=self.ai_policy_store,
                audit_store=self.ai_audit_store,
                llm_client_factory=llm_factory if callable(llm_factory) else self.get_llm_client,
                storage=lambda: self.storage,
                learning_manager=lambda: self.learning_manager,
            )

        self.background_triage_queue = BackgroundTriageQueue(
            orchestrator=self.ai_orchestrator,
            policy_store=self.ai_policy_store,
            event_store=self.event_ai_store,
            on_complete=self._on_background_triage_complete,
        )

        injected_logs = _get_session_override_obj(session_state, "log_store")
        self.log_store = injected_logs if isinstance(injected_logs, AppLogStore) else AppLogStore()
        self.log_store.set_on_entry(self._on_log_entry)
        self._log_handler = TuiLogHandler(self.log_store)
        self._attached_logger = logging.getLogger("soclens")
        self._attached_logger.addHandler(self._log_handler)

    @property
    def web_layout_profile(self) -> str:
        """Return the isolated workspace layout profile key for the Web UI."""
        return f"{self.storage.config.profile_name}::web"

    def get_effective_verify_ssl(self) -> bool | str:
        """Return the active SSL verification mode."""
        if self._verify_ssl_override is not None:
            return self._verify_ssl_override
        if self.rf_client is not None:
            cv = getattr(self.rf_client, "verify_ssl", None)
            if isinstance(cv, (bool, str)):
                return cv
        return get_rf_verify_ssl()

    def set_insecure_ssl(self, insecure: bool) -> bool | str:
        """Toggle session SSL verification mode."""
        target: bool | str = False if insecure else True
        if self.rf_client is not None:
            set_fn = getattr(self.rf_client, "set_verify_ssl", None)
            if callable(set_fn):
                set_fn(target)
        if target is False:
            suppress_insecure_ssl_warnings()
        self._verify_ssl_override = target
        self.sse_bus.publish("status", self.get_status_payload())
        return target

    def get_rf_client(self) -> RecordedFutureClient | None:
        if self.rf_client is not None:
            return self.rf_client
        if not get_rf_token(required=False):
            return None
        try:
            return RecordedFutureClient(
                verify_ssl=self.get_effective_verify_ssl(),
                stop_event=self.shutdown_event,
            )
        except ConfigurationError:
            return None

    def require_rf_client(self) -> RecordedFutureClient:
        if self.rf_client is not None:
            return self.rf_client
        return RecordedFutureClient(
            verify_ssl=self.get_effective_verify_ssl(),
            stop_event=self.shutdown_event,
        )

    def get_s1_client(self) -> SentinelOneClient | None:
        if self.s1_client is not None:
            return self.s1_client
        try:
            cfg = get_sentinelone_config(
                verify_ssl=self.get_effective_verify_ssl(),
                required=False,
            )
            if not cfg.has_auth:
                return None
            return SentinelOneClient(config=cfg, stop_event=self.shutdown_event)
        except ConfigurationError:
            return None

    def get_splunk_client(self) -> SplunkClient | None:
        if self.splunk_client is not None:
            return self.splunk_client
        try:
            cfg = get_splunk_config(required=False)
            if not cfg.has_auth:
                return None
            return SplunkClient()
        except ConfigurationError:
            return None

    def get_splunk_es_client(self) -> SplunkESClient | None:
        if self.splunk_es_client is not None:
            return self.splunk_es_client
        try:
            cfg = get_splunk_config(app=SPLUNK_ES_APP, required=False)
            if not cfg.has_auth:
                return None
            return SplunkESClient()
        except ConfigurationError:
            return None

    def get_osint_client(self) -> OSINTClient | None:
        if self.osint_client is not None:
            return self.osint_client
        return OSINTClient()

    def get_llm_client(self) -> LocalLLMClient:
        if self.llm_client is not None:
            return self.llm_client
        cfg = get_local_llm_config()
        return LocalLLMClient(cfg)

    def is_ai_killed(self) -> bool:
        """Return True when the AI kill switch is engaged."""
        if self._ai_kill_event.is_set():
            return True
        try:
            return bool(self.ai_policy_store.load().ai_kill_switch_active)
        except Exception:
            return False

    def set_ai_kill_switch(self, active: bool) -> dict[str, Any]:
        """Engage or resume the AI kill switch and publish SSE policy update."""
        active_bool = bool(active)
        if active_bool:
            self._ai_kill_event.set()
            halted_runs = self.ai_orchestrator.halt_all_active_runs()
            drained = self.background_triage_queue.halt_and_drain()
        else:
            self._ai_kill_event.clear()
            halted_runs = 0
            drained = 0
        updated = self.ai_policy_store.update(ai_kill_switch_active=active_bool)
        self.sse_bus.publish(
            "ai_policy_updated",
            {"ai_kill_switch_active": updated.ai_kill_switch_active, "learning_mode": updated.learning_mode},
        )
        self.sse_bus.publish("status", self.get_status_payload())
        return {
            "ai_kill_switch_active": updated.ai_kill_switch_active,
            "halted_runs": halted_runs,
            "drained_queue": drained,
        }

    def rebind_storage_from_settings(self) -> StorageManager:
        """Reload ``DatabaseConfig`` from active settings and rebind stores."""
        with self._lock:
            db_cfg = get_database_config(workspace_dir=self.workspace_dir)
            self.storage.rebind_config(db_cfg)
            try:
                self.storage.ensure_schema()
                self.storage.prune_expired(retention_days=db_cfg.retention_days)
                self.storage_error = None
            except Exception as exc:
                self.storage_error = str(
                    redact_web_payload(_sanitize_db_error(exc, db_cfg))
                )
                self.alert_cache.rebind_storage(None)
                self.ai_policy_store.rebind_storage(None)
                self.ai_audit_store.rebind_storage(None)
                self.event_ai_store.rebind_storage(None)
                self.sse_bus.publish("status", self.get_status_payload())
                raise
            self.alert_cache.rebind_storage(self.storage)
            self.ai_policy_store.rebind_storage(self.storage)
            self.ai_audit_store.rebind_storage(self.storage)
            self.event_ai_store.rebind_storage(self.storage)
            try:
                self.learning_manager.load_base_knowledge(self.workspace_dir)
            except Exception:
                pass
            self.sse_bus.publish("status", self.get_status_payload())
            return self.storage

    def _on_log_entry(self, entry: LogEntry) -> None:
        if self.shutdown_event.is_set():
            return
        self.sse_bus.publish(
            "log",
            {
                "timestamp": entry.timestamp,
                "level": entry.level,
                "source": entry.source,
                "logger_name": entry.logger_name,
                "message": entry.message,
                "created_utc": entry.created_utc.isoformat() if entry.created_utc else None,
            },
        )

    def _on_background_triage_complete(
        self,
        event: UniqueEvent,
        result: InvestigationResult,
    ) -> None:
        if self.shutdown_event.is_set():
            return
        self.sse_bus.publish(
            "triage_update",
            {
                "event_key": event.event_key,
                "source_kind": event.source_kind,
                "title": event.title,
                "run_id": result.run_id,
                "status": result.status,
                "provider": result.provider,
                "model": result.model,
                "timestamp": result.timestamp,
            },
        )

    def get_status_payload(self) -> dict[str, Any]:
        """Return non-sensitive runtime status metadata."""
        total_logs, warn_logs, err_logs = self.log_store.counts()
        try:
            learning_mode = self.learning_manager.get_learning_mode()
        except Exception:
            learning_mode = "manual"
        return {
            "ok": True,
            "admin_enabled": self.admin_enabled,
            "dry_run": self.dry_run,
            "version": __version__,
            "workstation_id": self.storage.config.workstation_id,
            "profile_name": self.storage.config.profile_name,
            "web_layout_profile": self.web_layout_profile,
            "dialect": self.storage.dialect,
            "storage_ok": self.storage_error is None,
            "storage_error": self.storage_error,
            "ai_kill_switch_active": self.is_ai_killed(),
            "learning_mode": learning_mode,
            "settings_locked": is_settings_locked(),
            "verify_ssl": self.get_effective_verify_ssl(),
            "background_triage_pending": self.background_triage_queue.pending_count(),
            "log_counts": {
                "total": total_logs,
                "warning": warn_logs,
                "error": err_logs,
            },
        }

    def request_shutdown(self) -> None:
        """Signal server shutdown, stop workers, and emit SSE shutdown."""
        if self.shutdown_event.is_set():
            return
        self.shutdown_event.set()
        try:
            self.ai_orchestrator.halt_all_active_runs()
        except Exception:
            pass
        try:
            self.background_triage_queue.stop(timeout=2.0)
        except Exception:
            pass
        self.sse_bus.close_all()
        if self.server_ref is not None:
            try:
                self.server_ref.should_exit = True
            except Exception:
                pass
        self.cleanup()

    def cleanup(self) -> None:
        """Release resources, detach handlers, and purge process-memory secrets."""
        with self._lock:
            if self._cleaned_up:
                return
            self._cleaned_up = True
            self.shutdown_event.set()
            try:
                self.sse_bus.close_all()
            except Exception:
                pass
            try:
                self.log_store.set_on_entry(None)
                self._attached_logger.removeHandler(self._log_handler)
            except Exception:
                pass
            try:
                self.background_triage_queue.stop(timeout=2.0)
            except Exception:
                pass
            try:
                self.auth_manager.clear_sessions()
            except Exception:
                pass
            try:
                clear_session_overrides()
                clear_unlocked_keys()
            except Exception:
                pass
            try:
                self.storage.dispose()
            except Exception:
                pass
