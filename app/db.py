"""Database layer. SQLAlchemy Core builds every query with bound parameters,
so user input is never concatenated into SQL (SQL-injection layer 1)."""
import os
from sqlalchemy import (create_engine, MetaData, Table, Column, Integer,
                        String, Text, DateTime, func)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data.db")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
metadata = MetaData()

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(30), unique=True, nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("created_at", DateTime, server_default=func.now()),
)

records = Table(
    "records", metadata,
    Column("id", Integer, primary_key=True),
    # UNIQUE constraint = last line of defence against duplicates (Task 1)
    Column("fingerprint", String(64), unique=True, nullable=False),
    Column("name", String(100), nullable=False),
    Column("email_enc", Text, nullable=False),   # AES-256-GCM ciphertext
    Column("phone_enc", Text, nullable=False),   # AES-256-GCM ciphertext
    Column("created_at", DateTime, server_default=func.now()),
)

rejected = Table(
    "rejected_entries", metadata,
    Column("id", Integer, primary_key=True),
    Column("fingerprint", String(64)),
    Column("classification", String(20), nullable=False),  # redundant | false_positive
    Column("reason", String(255), nullable=False),
    Column("created_at", DateTime, server_default=func.now()),
)


def init_db():
    metadata.create_all(engine)
