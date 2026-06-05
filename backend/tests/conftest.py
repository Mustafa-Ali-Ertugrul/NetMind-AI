"""Shared pytest fixtures and SQLite type shims.

The ORM models in backend.storage.models use Postgres-only types
(INET, JSONB, PG_UUID). For unit tests we need them to compile to
SQLite-friendly equivalents. This conftest registers type compilers
that map each Postgres type to a TEXT/JSON/CHAR(36) representation.
The PostgreSQL compilation path is unchanged.
"""

from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID
from sqlalchemy.ext.compiler import compiles


@compiles(INET, "sqlite")
def _compile_inet_sqlite(_type, _compiler, **_kw):
    return "TEXT"


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type, _compiler, **_kw):
    return "JSON"


@compiles(PG_UUID, "sqlite")
def _compile_pguuid_sqlite(_type, _compiler, **_kw):
    return "CHAR(36)"
