from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "")
if not SQLALCHEMY_DATABASE_URL:
    raise RuntimeError("CRITICAL ERROR: DATABASE_URL environment variable is missing. Halting boot sequence.")

# Connect args and pool args specific to SQLite vs Postgres
connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
    "pool_recycle": 1800,
}

if "postgresql" in SQLALCHEMY_DATABASE_URL:
    connect_args["connect_timeout"] = 5
    _db_sslmode = os.getenv("DB_SSLMODE", "verify-full")
    # The default is secure, but nothing previously stopped DB_SSLMODE from
    # being explicitly set to "disable"/"allow"/"prefer" -- all of which
    # either skip encryption entirely or silently downgrade to plaintext if
    # the server doesn't offer TLS. Fail closed on a weak value instead of
    # letting a misconfiguration connect unencrypted or unverified.
    if _db_sslmode not in ("require", "verify-ca", "verify-full"):
        raise RuntimeError(
            f"DB_SSLMODE={_db_sslmode!r} is not acceptable for a Postgres "
            "connection -- must be one of: require, verify-ca, verify-full."
        )
    connect_args["sslmode"] = _db_sslmode
    engine_kwargs.update({
        "pool_size": 20,
        "max_overflow": 20,
        "pool_timeout": 5,
    })
elif "sqlite" in SQLALCHEMY_DATABASE_URL:
    connect_args["timeout"] = 5
    connect_args["check_same_thread"] = False

engine_kwargs["connect_args"] = connect_args

# Sized pool with strict timeout to prevent threadpool starvation
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    **engine_kwargs
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# MIGRATION: index for cursor pagination
# execute via alembic or sqlalchemy event: Index('ix_alert_id_desc', Alert.id.desc()).create(bind=engine)
