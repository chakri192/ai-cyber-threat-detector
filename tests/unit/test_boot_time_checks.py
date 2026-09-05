"""Boot-time configuration checks in api/auth.py and api/database.py.

Both run at module IMPORT time, so they can't be exercised by importing
the module once and calling a function -- by the time a test file runs,
api.auth/api.database are already imported (and other tests depend on
that shared state: the same engine, the same JWT_SECRET). Each scenario
here is spawned as a fresh subprocess with its own environment instead,
so a raised RuntimeError is observed as a real import failure rather
than something worked around via importlib.reload() poisoning shared
module state for every other test in the session.
"""
import os
import subprocess
import sys

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _run_import(module, env_overrides):
    env = {
        **os.environ,
        "PYTHONPATH": _PROJECT_ROOT,
        "TSOC_API_KEY": "k",
        "TSOC_JWT_SECRET": "test-only-jwt-secret-do-not-use-in-prod",
        "DATABASE_URL": "sqlite:///./_test_boot_check.db",
        "REDIS_SSL": "false",
        "REDIS_PASSWORD": "x",
    }
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        env=env,
        cwd=_PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestJwtSecretLengthEnforcement:
    def test_short_jwt_secret_fails_at_import(self):
        result = _run_import("api.auth", {"TSOC_JWT_SECRET": "too-short"})
        assert result.returncode != 0
        assert "TSOC_JWT_SECRET" in result.stderr
        assert ">=32 bytes" in result.stderr

    def test_32_byte_jwt_secret_imports_cleanly(self):
        result = _run_import("api.auth", {"TSOC_JWT_SECRET": "a" * 32})
        assert result.returncode == 0, result.stderr

    def test_unset_jwt_secret_still_imports_cleanly(self):
        # Intentionally lazy: a deployment using only the static service
        # key should not be forced to configure a JWT secret it never uses.
        env = {
            **os.environ,
            "PYTHONPATH": _PROJECT_ROOT,
            "TSOC_API_KEY": "k",
            "DATABASE_URL": "sqlite:///./_test_boot_check.db",
            "REDIS_SSL": "false",
            "REDIS_PASSWORD": "x",
        }
        env.pop("TSOC_JWT_SECRET", None)
        result = subprocess.run(
            [sys.executable, "-c", "import api.auth; assert api.auth.JWT_SECRET is None"],
            env=env, cwd=_PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr


class TestPostgresSslModeEnforcement:
    def test_disabled_sslmode_fails_at_import(self):
        result = _run_import("api.database", {
            "DATABASE_URL": "postgresql://user:pass@nonexistent-host/db",
            "DB_SSLMODE": "disable",
        })
        assert result.returncode != 0
        assert "DB_SSLMODE" in result.stderr

    def test_prefer_sslmode_fails_at_import(self):
        # "prefer" silently downgrades to plaintext if the server doesn't
        # offer TLS -- not an acceptable default for this platform.
        result = _run_import("api.database", {
            "DATABASE_URL": "postgresql://user:pass@nonexistent-host/db",
            "DB_SSLMODE": "prefer",
        })
        assert result.returncode != 0
        assert "DB_SSLMODE" in result.stderr

    def test_verify_full_sslmode_imports_cleanly(self):
        result = _run_import("api.database", {
            "DATABASE_URL": "postgresql://user:pass@nonexistent-host/db",
            "DB_SSLMODE": "verify-full",
        })
        assert result.returncode == 0, result.stderr

    def test_require_sslmode_imports_cleanly(self):
        result = _run_import("api.database", {
            "DATABASE_URL": "postgresql://user:pass@nonexistent-host/db",
            "DB_SSLMODE": "require",
        })
        assert result.returncode == 0, result.stderr

    def test_sqlite_urls_are_unaffected_by_the_postgres_check(self):
        result = _run_import("api.database", {
            "DATABASE_URL": "sqlite:///./_test_boot_check.db",
            "DB_SSLMODE": "disable",  # irrelevant for sqlite, must not raise
        })
        assert result.returncode == 0, result.stderr

    def test_postgres_connection_pool_is_bounded_not_unbounded(self):
        # Not a live pool-exhaustion load test (sqlite -- what the rest of
        # this suite runs against -- has no comparable bounded-pool concept
        # to exhaust); this at least confirms the bounded-pool
        # configuration a real Postgres deployment relies on is actually
        # set, rather than silently missing.
        env = {
            **os.environ,
            "PYTHONPATH": _PROJECT_ROOT,
            "DATABASE_URL": "postgresql://user:pass@nonexistent-host/db",
            "DB_SSLMODE": "verify-full",
        }
        result = subprocess.run(
            [sys.executable, "-c",
             "import api.database as d; print(d.engine_kwargs['pool_size'], "
             "d.engine_kwargs['max_overflow'], d.engine_kwargs['pool_timeout'])"],
            env=env, cwd=_PROJECT_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        pool_size, max_overflow, pool_timeout = map(int, result.stdout.split())
        assert 0 < pool_size <= 50
        assert 0 < max_overflow <= 50
        assert 0 < pool_timeout <= 30
