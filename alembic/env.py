from logging.config import fileConfig
import os
import re

from sqlalchemy import engine_from_config, pool

# Import all models so that metadata is populated for autogenerate
import api.models
from alembic import context
from api.models.base import Base

# Reference ``api.models`` after import so static analysers (CodeQL) see the
# import as used; importing it for side effects is required to populate
# ``Base.metadata`` for autogenerate.
assert api.models is not None


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override sqlalchemy.url with DATABASE_URL env var when available (e.g. in Docker/production)
db_url = os.environ.get("DATABASE_URL")
if db_url:
    # Alembic requires a synchronous driver; normalise to psycopg v3
    db_url = re.sub(r"postgresql(?:\+\w+)?://", "postgresql+psycopg://", db_url)
    config.set_main_option("sqlalchemy.url", db_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
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
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
