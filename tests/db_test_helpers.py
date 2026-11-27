"""Self-contained mock DB-API 2.0 drivers (pg8000 / PyMySQL) and TLS cert helper for unit tests."""

from __future__ import annotations

import re
import sys
import types
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest


class MockDBError(Exception):
    """Base DB-API 2.0 mock exception."""


class MockDBInterfaceError(MockDBError):
    """DB-API 2.0 InterfaceError."""


class MockDBDatabaseError(MockDBError):
    """DB-API 2.0 DatabaseError."""


class MockDBOperationalError(MockDBDatabaseError):
    """DB-API 2.0 OperationalError."""


class MockDBProgrammingError(MockDBDatabaseError):
    """DB-API 2.0 ProgrammingError."""


def make_sample_ca_cert_pem() -> str:
    """Generate a valid self-signed X.509 CA certificate PEM for TLS connection tests."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "soclens-mock-ca.internal.example")]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _skip_sql_noncode(sql: str, idx: int) -> tuple[int, bool]:
    n = len(sql)
    ch = sql[idx]
    if ch in ("'", '"', "`"):
        quote = ch
        i = idx + 1
        while i < n:
            c = sql[i]
            if c == "\\" and quote == "'" and i + 1 < n:
                i += 2
                continue
            if c == quote:
                if i + 1 < n and sql[i + 1] == quote:
                    i += 2
                    continue
                return i + 1, True
            i += 1
        return n, True
    if ch == "[":
        end = sql.find("]", idx + 1)
        return (end + 1 if end != -1 else n), True
    if ch == "-" and idx + 1 < n and sql[idx + 1] == "-":
        nl = sql.find("\n", idx + 2)
        return (nl + 1 if nl != -1 else n), True
    if ch == "/" and idx + 1 < n and sql[idx + 1] == "*":
        end = sql.find("*/", idx + 2)
        return (end + 2 if end != -1 else n), True
    return idx, False


def _read_sql_word(sql: str, idx: int) -> tuple[str, int]:
    n = len(sql)
    end = idx
    while end < n and (sql[end].isalnum() or sql[end] in ("_", "$")):
        end += 1
    return sql[idx:end], end


def _split_top_level_csv(sql: str) -> list[str]:
    items: list[str] = []
    depth = 0
    start = 0
    i = 0
    n = len(sql)
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql, i)
        if skipped:
            i = next_i
            continue
        ch = sql[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            part = sql[start:i].strip()
            if part:
                items.append(part)
            start = i + 1
        i += 1
    tail = sql[start:].strip()
    if tail:
        items.append(tail)
    return items


def _extract_projection_name(expr: str) -> str:
    s = expr.strip()
    if not s:
        return "result"
    depth = 0
    i = 0
    n = len(s)
    last_as_after: int | None = None
    last_ws_parts: list[str] = []
    part_start = 0
    while i < n:
        next_i, skipped = _skip_sql_noncode(s, i)
        if skipped:
            i = next_i
            continue
        ch = s[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0:
            if ch.isspace():
                seg = s[part_start:i].strip()
                if seg:
                    last_ws_parts.append(seg)
                part_start = i + 1
                i += 1
                continue
            if (ch.isalpha() or ch == "_") and (
                i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_")
            ):
                word, end = _read_sql_word(s, i)
                if word.lower() == "as" and (
                    end == n or s[end].isspace() or s[end] in ('"', "`", "[")
                ):
                    last_as_after = end
                i = end
                continue
        i += 1
    tail_seg = s[part_start:].strip()
    if tail_seg:
        last_ws_parts.append(tail_seg)
    if last_as_after is not None:
        alias = s[last_as_after:].strip().strip('"`[]')
        if alias:
            return alias
    target = last_ws_parts[-1] if last_ws_parts else s
    dots: list[int] = []
    ti = 0
    tn = len(target)
    tdepth = 0
    while ti < tn:
        next_ti, skipped = _skip_sql_noncode(target, ti)
        if skipped:
            ti = next_ti
            continue
        if target[ti] == "(":
            tdepth += 1
        elif target[ti] == ")":
            tdepth = max(0, tdepth - 1)
        elif target[ti] == "." and tdepth == 0:
            dots.append(ti)
        ti += 1
    col = target[dots[-1] + 1 :] if dots else target
    cleaned = col.strip().strip('"`[]')
    return cleaned or "result"


def _extract_select_projection(sql: str) -> tuple[list[str], list[str], bool]:
    n = len(sql)
    depth = 0
    i = 0
    select_end: int | None = None
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql, i)
        if skipped:
            i = next_i
            continue
        ch = sql[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0 and (ch.isalpha() or ch == "_"):
            word, end = _read_sql_word(sql, i)
            if word.lower() == "select":
                select_end = end
                break
            i = end
            continue
        i += 1
    if select_end is None:
        return [], ["result"], False

    i = select_end
    while i < n:
        if sql[i].isspace():
            i += 1
            continue
        if sql.startswith("--", i) or sql.startswith("/*", i):
            next_i, _ = _skip_sql_noncode(sql, i)
            i = next_i
            continue
        if sql[i].isalpha() or sql[i] == "_":
            word, end = _read_sql_word(sql, i)
            if word.lower() in ("distinct", "all"):
                i = end
                continue
        break

    proj_start = i
    proj_end = n
    stop_keywords = {
        "from",
        "where",
        "group",
        "having",
        "order",
        "limit",
        "offset",
        "fetch",
        "for",
        "union",
        "intersect",
        "except",
        "window",
        "into",
    }
    depth = 0
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql, i)
        if skipped:
            i = next_i
            continue
        ch = sql[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0:
            if ch == ";":
                proj_end = i
                break
            if (ch.isalpha() or ch == "_") and (
                i == 0 or not (sql[i - 1].isalnum() or sql[i - 1] == "_")
            ):
                word, end = _read_sql_word(sql, i)
                if word.lower() in stop_keywords:
                    proj_end = i
                    break
                i = end
                continue
        i += 1

    raw_items = _split_top_level_csv(sql[proj_start:proj_end])
    cols = [_extract_projection_name(item) for item in raw_items]
    if not cols or cols == ["*"] or any(c == "*" or c.endswith(".*") for c in cols):
        cols = ["result"]

    has_group_by = False
    depth = 0
    gi = proj_end
    while gi < n:
        next_gi, skipped = _skip_sql_noncode(sql, gi)
        if skipped:
            gi = next_gi
            continue
        ch = sql[gi]
        if ch == "(":
            depth += 1
            gi += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            gi += 1
            continue
        if (
            depth == 0
            and (ch.isalpha() or ch == "_")
            and (gi == 0 or not (sql[gi - 1].isalnum() or sql[gi - 1] == "_"))
        ):
            word, end = _read_sql_word(sql, gi)
            if word.lower() == "group":
                k = end
                while k < n and sql[k].isspace():
                    k += 1
                if k < n and (sql[k].isalpha() or sql[k] == "_"):
                    next_word, _ = _read_sql_word(sql, k)
                    if next_word.lower() == "by":
                        has_group_by = True
                        break
            gi = end
            continue
        gi += 1

    return raw_items, cols, has_group_by


def _split_returning_clause(sql: str) -> tuple[str, str] | None:
    n = len(sql)
    depth = 0
    i = 0
    last_pos: int | None = None
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql, i)
        if skipped:
            i = next_i
            continue
        ch = sql[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if (
            depth == 0
            and (ch.isalpha() or ch == "_")
            and (i == 0 or not (sql[i - 1].isalnum() or sql[i - 1] == "_"))
        ):
            word, end = _read_sql_word(sql, i)
            if word.lower() == "returning":
                last_pos = i
            i = end
            continue
        i += 1
    if last_pos is None:
        return None
    return sql[:last_pos], sql[last_pos + len("returning") :]


def _count_insert_value_tuples(sql_before_returning: str) -> int:
    n = len(sql_before_returning)
    depth = 0
    i = 0
    values_end: int | None = None
    values_depth = 0
    while i < n:
        next_i, skipped = _skip_sql_noncode(sql_before_returning, i)
        if skipped:
            i = next_i
            continue
        ch = sql_before_returning[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if (ch.isalpha() or ch == "_") and (
            i == 0
            or not (sql_before_returning[i - 1].isalnum() or sql_before_returning[i - 1] == "_")
        ):
            word, end = _read_sql_word(sql_before_returning, i)
            if word.lower() == "values":
                k = end
                while k < n:
                    if sql_before_returning[k].isspace():
                        k += 1
                        continue
                    next_k, skipped_k = _skip_sql_noncode(sql_before_returning, k)
                    if skipped_k:
                        k = next_k
                        continue
                    break
                if k < n and sql_before_returning[k] == "(":
                    values_end = k
                    values_depth = depth
                    break
            i = end
            continue
        i += 1

    if values_end is None:
        return 1

    count = 0
    i = values_end
    depth = values_depth
    while i < n:
        if sql_before_returning[i].isspace():
            i += 1
            continue
        next_i, skipped = _skip_sql_noncode(sql_before_returning, i)
        if skipped:
            i = next_i
            continue
        ch = sql_before_returning[i]
        if ch == "(" and depth == values_depth:
            count += 1
            depth += 1
            i += 1
            while i < n and depth > values_depth:
                next_inner, skipped_inner = _skip_sql_noncode(sql_before_returning, i)
                if skipped_inner:
                    i = next_inner
                    continue
                if sql_before_returning[i] == "(":
                    depth += 1
                elif sql_before_returning[i] == ")":
                    depth -= 1
                i += 1
            while i < n:
                if sql_before_returning[i].isspace():
                    i += 1
                    continue
                next_sep, skipped_sep = _skip_sql_noncode(sql_before_returning, i)
                if skipped_sep:
                    i = next_sep
                    continue
                break
            if i < n and sql_before_returning[i] == ",":
                i += 1
                continue
            break
        break
    return max(1, count)


class MockDBCursor:
    """Lightweight DB-API 2.0 cursor recording queries and returning dialect probe rows."""

    def __init__(self, connection: MockDBConnection) -> None:
        self._conn = connection
        self._rows: list[tuple[Any, ...]] = []
        self._idx = 0
        self.description: list[tuple[Any, ...]] | None = None
        self.rowcount: int = -1
        self.lastrowid: int | None = None
        self.arraysize: int = 1
        self.closed: bool = False

    def execute(self, operation: str, parameters: Any = None) -> MockDBCursor:
        sql = str(operation or "")
        self._conn.driver.executed_sql.append((sql, parameters))
        lowered = " ".join(sql.lower().split())

        if self._conn.driver.query_responder is not None:
            custom = self._conn.driver.query_responder(sql, parameters)
            if custom is not None:
                cols, rows = custom
                self.description = [(c, None, None, None, None, None, None) for c in cols]
                self._rows = [tuple(r) for r in rows]
                self._idx = 0
                self.rowcount = len(self._rows)
                return self

        if (
            "pg_catalog.version()" in lowered
            or "select version()" in lowered
            or "select @@version" in lowered
        ):
            ver = (
                "PostgreSQL 16.4 on x86_64-pc-linux-gnu"
                if self._conn.driver.dialect == "postgres"
                else "8.0.39"
            )
            self.description = [("version", None, None, None, None, None, None)]
            self._rows = [(ver,)]
        elif "standard_conforming_strings" in lowered:
            self.description = [
                ("standard_conforming_strings", None, None, None, None, None, None)
            ]
            self._rows = [("on",)]
        elif "show transaction isolation level" in lowered:
            self.description = [("transaction_isolation", None, None, None, None, None, None)]
            self._rows = [("read committed",)]
        elif "show transaction_read_only" in lowered:
            self.description = [("transaction_read_only", None, None, None, None, None, None)]
            self._rows = [("off",)]
        elif "show transaction_deferrable" in lowered:
            self.description = [("transaction_deferrable", None, None, None, None, None, None)]
            self._rows = [("off",)]
        elif "@@tx_isolation" in lowered or "@@transaction_isolation" in lowered:
            col = "tx_isolation" if "@@tx_isolation" in lowered else "transaction_isolation"
            self.description = [(col, None, None, None, None, None, None)]
            self._rows = [("REPEATABLE-READ",)]
        elif "@@lower_case_table_names" in lowered:
            self.description = [("@@lower_case_table_names", None, None, None, None, None, None)]
            self._rows = [(0,)]
        elif "@@sql_mode" in lowered:
            self.description = [("@@sql_mode", None, None, None, None, None, None)]
            self._rows = [("STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION",)]
        elif "current_schema" in lowered:
            self.description = [("current_schema", None, None, None, None, None, None)]
            self._rows = [("public",)]
        elif "select database()" in lowered:
            self.description = [("database()", None, None, None, None, None, None)]
            self._rows = [(self._conn.kwargs.get("database") or "soclens_db",)]
        elif "show variables" in lowered or "show sql_mode" in lowered:
            self.description = [
                ("Variable_name", None, None, None, None, None, None),
                ("Value", None, None, None, None, None, None),
            ]
            if "lower_case_table_names" in lowered:
                self._rows = [("lower_case_table_names", "0")]
            else:
                self._rows = [("sql_mode", "STRICT_TRANS_TABLES")]
        elif "show tables" in lowered or "show full tables" in lowered:
            self.description = [("Tables_in_soclens_db", None, None, None, None, None, None)]
            self._rows = []
        elif (
            lowered.startswith("describe ")
            or "show create table" in lowered
            or "pg_catalog.pg_class" in lowered
            or "pg_tables" in lowered
            or "information_schema" in lowered
            or lowered.startswith("show ")
        ):
            self.description = [("col", None, None, None, None, None, None)]
            self._rows = []
        elif (returning_split := _split_returning_clause(sql)) is not None:
            before_returning, returning_part = returning_split
            ret_items = _split_top_level_csv(returning_part)
            ret_cols = [_extract_projection_name(c) for c in ret_items] or ["id"]
            n_rows = (
                _count_insert_value_tuples(before_returning)
                if lowered.startswith("insert ")
                else 1
            )
            self.description = [
                (col_name, None, None, None, None, None, None) for col_name in ret_cols
            ]
            base_id = self._conn.driver.allocate_rowids(n_rows)
            self.lastrowid = base_id + n_rows - 1
            self._rows = [
                tuple(base_id + offset for _ in ret_cols) for offset in range(n_rows)
            ]
            self._idx = 0
            self.rowcount = n_rows
            return self
        elif re.match(r"^select\s+1(?:\s+from\s+dual)?\s*;?$", lowered):
            self.description = [("col1", None, None, None, None, None, None)]
            self._rows = [(1,)]
        elif lowered.startswith(("select ", "with ")):
            raw_items, cols, has_group_by = _extract_select_projection(sql)
            self.description = [
                (col_name, None, None, None, None, None, None) for col_name in cols
            ]
            if (
                len(raw_items) == 1
                and not has_group_by
                and re.match(r"^count\s*\(", raw_items[0].strip(), re.IGNORECASE)
            ):
                self._rows = [(0,)]
            else:
                self._rows = []
        elif lowered.startswith("insert "):
            n_rows = _count_insert_value_tuples(sql)
            base_id = self._conn.driver.allocate_rowids(n_rows)
            self.lastrowid = base_id + n_rows - 1
            self.description = None
            self._rows = []
            self._idx = 0
            self.rowcount = n_rows
            return self
        else:
            self.description = None
            self._rows = []

        self._idx = 0
        self.rowcount = len(self._rows) if self.description is not None else 0
        return self

    def executemany(self, operation: str, seq_of_parameters: Sequence[Any]) -> MockDBCursor:
        for params in seq_of_parameters:
            self.execute(operation, params)
        return self

    def fetchone(self) -> tuple[Any, ...] | None:
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    def fetchmany(self, size: int | None = None) -> list[tuple[Any, ...]]:
        count = self.arraysize if size is None else max(0, int(size))
        end = self._idx + count
        batch = self._rows[self._idx : end]
        self._idx = min(len(self._rows), end)
        return list(batch)

    def fetchall(self) -> list[tuple[Any, ...]]:
        rest = self._rows[self._idx :]
        self._idx = len(self._rows)
        return list(rest)

    def setinputsizes(self, sizes: Any) -> None:
        return None

    def setoutputsize(self, size: Any, column: Any = None) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> MockDBCursor:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def __iter__(self) -> Iterator[tuple[Any, ...]]:
        return iter(self.fetchall())


class MockDBConnection:
    """Lightweight DB-API 2.0 connection capturing TLS/SSL parameters and transactions."""

    def __init__(self, driver: MockDBAPIDriver, kwargs: dict[str, Any]) -> None:
        self.driver = driver
        self.dialect = driver.dialect
        self.kwargs = dict(kwargs)
        self.closed = False
        self._autocommit = False
        self.committed = 0
        self.rolled_back = 0
        if self.dialect == "postgres":
            self.autocommit: Any = False
            self.py_types: dict[Any, int] = {
                str: 25,
                bytes: 17,
                int: 23,
                float: 701,
                bool: 16,
            }
        else:
            self.autocommit = self._set_autocommit

    def _set_autocommit(self, value: bool) -> None:
        self._autocommit = bool(value)

    def get_autocommit(self) -> bool:
        if self.dialect == "postgres":
            return bool(self.autocommit)
        return self._autocommit

    def character_set_name(self) -> str:
        return str(self.kwargs.get("charset") or "utf8mb4")

    def register_in_adapter(self, oid: int, fn: Any) -> None:
        return None

    def cursor(self, *args: Any, **kwargs: Any) -> MockDBCursor:
        return MockDBCursor(self)

    def commit(self) -> None:
        self.committed += 1

    def rollback(self) -> None:
        self.rolled_back += 1

    def ping(self, reconnect: bool = True) -> None:
        return None

    def select_db(self, db: str) -> None:
        self.kwargs["database"] = db

    def set_character_set(self, charset: str) -> None:
        self.kwargs["charset"] = charset

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> MockDBConnection:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


@dataclass
class MockDBAPIDriver:
    """Mock DB-API 2.0 module shim for ``pg8000`` or ``pymysql``."""

    dialect: str
    apilevel: str = "2.0"
    threadsafety: int = 1
    paramstyle: str = "format"
    __version__: str = "1.31.2"
    Error: type[Exception] = MockDBError
    InterfaceError: type[Exception] = MockDBInterfaceError
    DatabaseError: type[Exception] = MockDBDatabaseError
    OperationalError: type[Exception] = MockDBOperationalError
    ProgrammingError: type[Exception] = MockDBProgrammingError
    connect_calls: list[dict[str, Any]] = field(default_factory=list)
    executed_sql: list[tuple[str, Any]] = field(default_factory=list)
    connections: list[MockDBConnection] = field(default_factory=list)
    query_responder: (
        Callable[[str, Any], tuple[list[str], list[tuple[Any, ...]]] | None] | None
    ) = None
    fail_on_connect: Exception | None = None
    _next_rowid: int = field(default=1, init=False, repr=False)

    def allocate_rowids(self, count: int = 1) -> int:
        base = self._next_rowid
        self._next_rowid += max(1, count)
        return base

    def connect(self, *args: Any, **kwargs: Any) -> MockDBConnection:
        if self.fail_on_connect is not None:
            raise self.fail_on_connect
        recorded = dict(kwargs)
        if args:
            recorded["_positional_args"] = list(args)
        self.connect_calls.append(recorded)
        conn = MockDBConnection(self, recorded)
        self.connections.append(conn)
        return conn


def install_mock_db_drivers(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pg_responder: (
        Callable[[str, Any], tuple[list[str], list[tuple[Any, ...]]] | None] | None
    ) = None,
    mysql_responder: (
        Callable[[str, Any], tuple[list[str], list[tuple[Any, ...]]] | None] | None
    ) = None,
) -> dict[str, MockDBAPIDriver]:
    """Inject mock ``pg8000`` and ``pymysql`` DB-API 2.0 modules into ``sys.modules``."""
    pg_driver = MockDBAPIDriver(
        dialect="postgres",
        paramstyle="format",
        __version__="1.31.2",
        query_responder=pg_responder,
    )
    mysql_driver = MockDBAPIDriver(
        dialect="mysql",
        paramstyle="pyformat",
        __version__="1.1.1",
        query_responder=mysql_responder,
    )

    def _build_module(name: str, drv: MockDBAPIDriver) -> types.ModuleType:
        mod = types.ModuleType(name)
        mod.apilevel = drv.apilevel  # type: ignore[attr-defined]
        mod.threadsafety = drv.threadsafety  # type: ignore[attr-defined]
        mod.paramstyle = drv.paramstyle  # type: ignore[attr-defined]
        mod.__version__ = drv.__version__  # type: ignore[attr-defined]
        mod.version_info = tuple(int(part) for part in drv.__version__.split("."))  # type: ignore[attr-defined]
        mod.connect = drv.connect  # type: ignore[attr-defined]
        mod.Connection = MockDBConnection  # type: ignore[attr-defined]
        mod.Cursor = MockDBCursor  # type: ignore[attr-defined]
        mod.Error = drv.Error  # type: ignore[attr-defined]
        mod.InterfaceError = drv.InterfaceError  # type: ignore[attr-defined]
        mod.DatabaseError = drv.DatabaseError  # type: ignore[attr-defined]
        mod.OperationalError = drv.OperationalError  # type: ignore[attr-defined]
        mod.ProgrammingError = drv.ProgrammingError  # type: ignore[attr-defined]
        mod.Binary = bytes  # type: ignore[attr-defined]
        return mod

    pg_mod = _build_module("pg8000", pg_driver)
    pg_dbapi_mod = _build_module("pg8000.dbapi", pg_driver)
    pg_native_mod = _build_module("pg8000.native", pg_driver)
    pg_exc_mod = types.ModuleType("pg8000.exceptions")
    pg_exc_mod.Error = pg_driver.Error  # type: ignore[attr-defined]
    pg_exc_mod.InterfaceError = pg_driver.InterfaceError  # type: ignore[attr-defined]
    pg_exc_mod.DatabaseError = pg_driver.DatabaseError  # type: ignore[attr-defined]
    pg_mod.dbapi = pg_dbapi_mod  # type: ignore[attr-defined]
    pg_mod.native = pg_native_mod  # type: ignore[attr-defined]
    pg_mod.exceptions = pg_exc_mod  # type: ignore[attr-defined]

    mysql_mod = _build_module("pymysql", mysql_driver)
    mysql_mod.VERSION_STRING = mysql_driver.__version__  # type: ignore[attr-defined]
    mysql_cursors_mod = types.ModuleType("pymysql.cursors")

    class _MockDictCursor(MockDBCursor):
        pass

    mysql_cursors_mod.Cursor = MockDBCursor  # type: ignore[attr-defined]
    mysql_cursors_mod.DictCursor = _MockDictCursor  # type: ignore[attr-defined]
    mysql_cursors_mod.SSCursor = MockDBCursor  # type: ignore[attr-defined]
    mysql_err_mod = types.ModuleType("pymysql.err")
    mysql_err_mod.Error = mysql_driver.Error  # type: ignore[attr-defined]
    mysql_err_mod.OperationalError = mysql_driver.OperationalError  # type: ignore[attr-defined]
    mysql_err_mod.ProgrammingError = mysql_driver.ProgrammingError  # type: ignore[attr-defined]
    mysql_mod.cursors = mysql_cursors_mod  # type: ignore[attr-defined]
    mysql_mod.err = mysql_err_mod  # type: ignore[attr-defined]

    for mod_name, mod_obj in (
        ("pg8000", pg_mod),
        ("pg8000.dbapi", pg_dbapi_mod),
        ("pg8000.native", pg_native_mod),
        ("pg8000.exceptions", pg_exc_mod),
        ("pymysql", mysql_mod),
        ("pymysql.cursors", mysql_cursors_mod),
        ("pymysql.err", mysql_err_mod),
    ):
        monkeypatch.setitem(sys.modules, mod_name, mod_obj)

    return {"postgres": pg_driver, "mysql": mysql_driver}
