import json

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


def get_prekey_bundle_with_opk(username: str) -> dict | None:
    """Return the user's public prekey bundle and atomically remove one OPK.

    Uses SELECT FOR UPDATE so concurrent requests can't hand the same OPK to two callers.
    Returns None if the user doesn't exist.  opk_pub/opk_id are None if no OPKs remain.
    """
    with DBConnection() as (conn, cur):
        cur.execute(
            "SELECT user_id, public_key FROM users WHERE username = %s FOR UPDATE",
            (username,),
        )
        row = cur.fetchone()
        if not row:
            return None

        bundle = json.loads(row["public_key"])
        opk_pubs = bundle.get("opk_pubs", [])

        opk = opk_pubs.pop(0) if opk_pubs else None

        if opk is not None:
            bundle["opk_pubs"] = opk_pubs
            cur.execute(
                "UPDATE users SET public_key = %s WHERE user_id = %s",
                (json.dumps(bundle), row["user_id"]),
            )
            conn.commit()

        return {
            "user_id":       str(row["user_id"]),
            "ik_sign_pub":   bundle["ik_sign_pub"],
            "ik_dh_pub":     bundle["ik_dh_pub"],
            "spk_pub":       bundle["spk_pub"],
            "spk_signature": bundle["spk_signature"],
            "opk_pub":       opk["key"] if opk else None,
            "opk_id":        opk["id"]  if opk else None,
        }


def get_opk_count(user_id: str) -> int:
    with DBConnection() as (_, cur):
        cur.execute("SELECT public_key FROM users WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            return 0
        return len(json.loads(row["public_key"]).get("opk_pubs", []))


def append_one_time_prekeys(user_id: str, new_opks: list[dict]) -> int:
    """Append new OPKs to the user's bundle. Returns the new total count."""
    with DBConnection() as (conn, cur):
        cur.execute(
            "SELECT public_key FROM users WHERE user_id = %s FOR UPDATE",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            return 0
        bundle = json.loads(row["public_key"])
        bundle["opk_pubs"].extend(new_opks)
        cur.execute(
            "UPDATE users SET public_key = %s WHERE user_id = %s",
            (json.dumps(bundle), user_id),
        )
        conn.commit()
        return len(bundle["opk_pubs"])


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
    header: str,
    signature: str,
    digest: str,
    blockchain_tx_hash: str | None = None,
) -> dict:
    with DBConnection() as (conn, cur):
        cur.execute(
            """
            INSERT INTO messages
                (sender_id, recipient_id, content_ciphertext, nonce, header, signature, digest, blockchain_tx_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (sender_id, recipient_id, content_ciphertext, nonce, header, signature, digest, blockchain_tx_hash),
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
            """
            SELECT m.*, u.username AS sender_username
            FROM messages m
            JOIN users u ON u.user_id = m.sender_id
            WHERE m.recipient_id = %s
            ORDER BY m.created_at ASC
            """,
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


def get_tx_hash_by_digest(digest: str) -> str | None:
    # Accept both "0x<hash>" and "<hash>" — normalize to try both variants
    without_prefix = digest.removeprefix("0x")
    with_prefix    = "0x" + without_prefix
    with DBConnection() as (_, cur):
        cur.execute(
            "SELECT blockchain_tx_hash FROM messages WHERE digest IN (%s, %s) LIMIT 1",
            (with_prefix, without_prefix),
        )
        row = cur.fetchone()
        return row["blockchain_tx_hash"] if row else None


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
