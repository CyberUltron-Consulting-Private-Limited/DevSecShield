from logging.config import fileConfig
import os
from urllib.parse import quote_plus

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from sqlalchemy import text
from sqlmodel import SQLModel
from alembic import context
from backend.new_models import *
from dotenv import load_dotenv

load_dotenv()


def _database_url() -> str:
    # Prefer PG_* the same way backend.get_db does. A host-local DATABASE_URL in
    # .env (localhost:4433 / RDS) will hang Alembic inside Docker.
    user = os.getenv("PG_USER")
    password = os.getenv("PG_USER_PASS")
    db = os.getenv("PG_DB")
    is_docker = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"
    host = os.getenv("PG_HOST", "devsecshield-postgres" if is_docker else "localhost")
    port = os.getenv("PG_PORT", "5432" if is_docker else "4433")
    if user and password and db:
        return (
            f"postgresql://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{db}"
        )
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    raise RuntimeError("DATABASE_URL or PG_USER/PG_USER_PASS/PG_DB must be set")


DATABASE_URL = _database_url()

# pg_advisory_lock key reserved for schema migrations ("DSS" + 1).
MIGRATION_LOCK_KEY = 0x44535301


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config
# Alembic ConfigParser treats % as interpolation — escape passwords.
config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))
# config.set_main_option("sqlalchemy.url", "sqlite:///C:\\Users\\HP\\Desktop\\DevSecShield\\backend\\database.db") # for testing only ⚠️

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = SQLModel.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        if connection.dialect.name == "postgresql":
            # One migrator at a time: containers that start together (the migrate one-shot, a backend or worker
            # started with migrations on) would otherwise run the same revision twice. The session-level lock is
            # held until this connection closes; a second migrator waits here, then finds the database at head.
            connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
            connection.commit()  # end the implicit transaction so Alembic opens (and commits) its own
        # One transaction per revision: a revision's locks (an ACCESS EXCLUSIVE from ADD CONSTRAINT on a table every
        # request reads) end with that revision, never span the other pending ones; a failure leaves the database at
        # the last revision that completed.
        context.configure(
            connection=connection, target_metadata=target_metadata, transaction_per_migration=True
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
