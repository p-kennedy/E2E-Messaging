from connection import DBConnection


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def create_user(username: str, password_hash: str, public_key: str) -> dict:
    with DBConnection() as (conn, cur):
        cur.execute(
            """
            INSERT INTO users (username, password_hash, public_key)
            VALUES (%s, %s, %s)
            RETURNING *
            """,
            (username, password_hash, public_key),
        )
        conn.commit()
        return dict(cur.fetchone())


def get_user_by_id(user_id: str) -> dict | None:
    with DBConnection() as (_, cur):
        cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_username(username: str) -> dict | None:
    with DBConnection() as (_, cur):
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_all_users() -> list[dict]:
    with DBConnection() as (_, cur):
        cur.execute("SELECT user_id, username, public_key, created_at FROM users")
        return [dict(r) for r in cur.fetchall()]


def update_user_password(user_id: str, new_password_hash: str) -> bool:
    with DBConnection() as (conn, cur):
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE user_id = %s",
            (new_password_hash, user_id),
        )
        conn.commit()
        return cur.rowcount > 0


def update_user_public_key(user_id: str, new_public_key: str) -> bool:
    with DBConnection() as (conn, cur):
        cur.execute(
            "UPDATE users SET public_key = %s WHERE user_id = %s",
            (new_public_key, user_id),
        )
        conn.commit()
        return cur.rowcount > 0


def delete_user(user_id: str) -> bool:
    with DBConnection() as (conn, cur):
        cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        conn.commit()
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def create_message(
    sender_id: str,
    recipient_id: str,
    content_ciphertext: str,
    nonce: str,
    digest: str,
    blockchain_tx_hash: str | None = None,
) -> dict:
    with DBConnection() as (conn, cur):
        cur.execute(
            """
            INSERT INTO messages
                (sender_id, recipient_id, content_ciphertext, nonce, digest, blockchain_tx_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (sender_id, recipient_id, content_ciphertext, nonce, digest, blockchain_tx_hash),
        )
        conn.commit()
        return dict(cur.fetchone())


def get_message_by_id(message_id: str) -> dict | None:
    with DBConnection() as (_, cur):
        cur.execute("SELECT * FROM messages WHERE message_id = %s", (message_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_messages_for_recipient(recipient_id: str) -> list[dict]:
    with DBConnection() as (_, cur):
        cur.execute(
            "SELECT * FROM messages WHERE recipient_id = %s ORDER BY created_at ASC",
            (recipient_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_messages_by_sender(sender_id: str) -> list[dict]:
    with DBConnection() as (_, cur):
        cur.execute(
            "SELECT * FROM messages WHERE sender_id = %s ORDER BY created_at ASC",
            (sender_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_conversation(user_a: str, user_b: str) -> list[dict]:
    with DBConnection() as (_, cur):
        cur.execute(
            """
            SELECT * FROM messages
            WHERE (sender_id = %s AND recipient_id = %s)
               OR (sender_id = %s AND recipient_id = %s)
            ORDER BY created_at ASC
            """,
            (user_a, user_b, user_b, user_a),
        )
        return [dict(r) for r in cur.fetchall()]


def update_blockchain_tx_hash(message_id: str, tx_hash: str) -> bool:
    with DBConnection() as (conn, cur):
        cur.execute(
            "UPDATE messages SET blockchain_tx_hash = %s WHERE message_id = %s",
            (tx_hash, message_id),
        )
        conn.commit()
        return cur.rowcount > 0


def delete_message(message_id: str) -> bool:
    with DBConnection() as (conn, cur):
        cur.execute("DELETE FROM messages WHERE message_id = %s", (message_id,))
        conn.commit()
        return cur.rowcount > 0
