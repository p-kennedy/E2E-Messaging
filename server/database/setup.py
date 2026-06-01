"""
Run once to create tables:  python -m server.database.setup
"""

from connection import DBConnection, init_pool

SCHEMA = """
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    user_id       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR     NOT NULL UNIQUE,
    password_hash VARCHAR     NOT NULL,
    public_key    VARCHAR     NOT NULL,
    created_at    TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS messages (
    message_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id           UUID        NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    recipient_id        UUID        NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    content_ciphertext  VARCHAR     NOT NULL,
    nonce               VARCHAR     NOT NULL,
    header              TEXT        NOT NULL,
    signature           VARCHAR     NOT NULL,
    digest              VARCHAR     NOT NULL,
    blockchain_tx_hash  VARCHAR,
    created_at          TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- Migration for databases created before header/signature columns were added
ALTER TABLE messages ADD COLUMN IF NOT EXISTS header    TEXT    NOT NULL DEFAULT '';
ALTER TABLE messages ADD COLUMN IF NOT EXISTS signature VARCHAR NOT NULL DEFAULT '';
"""


def create_tables() -> None:
    with DBConnection() as (conn, cur):
        cur.execute(SCHEMA)
        conn.commit()
    print("Tables created successfully.")


if __name__ == "__main__":
    init_pool()
    create_tables()
