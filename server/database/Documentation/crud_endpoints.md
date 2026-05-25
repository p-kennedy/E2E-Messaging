# CRUD Endpoints

All functions live in `server/database/crud.py`.

---

## Users

### Create

**`create_user(username, password_hash, public_key) -> dict`**

Inserts a new user. Returns the full created row.

```python
user = create_user("alice", "<bcrypt_hash>", "<public_key_pem>")
```

---

### Read

**`get_user_by_id(user_id) -> dict | None`**

Fetch a user by their UUID. Returns `None` if not found.

```python
user = get_user_by_id("550e8400-e29b-41d4-a716-446655440000")
```

**`get_user_by_username(username) -> dict | None`**

Fetch a user by username. Use this for login lookups.

```python
user = get_user_by_username("alice")
```

**`get_all_users() -> list[dict]`**

Returns all users (excludes `password_hash`).

```python
users = get_all_users()
```

---

### Update

**`update_user_password(user_id, new_password_hash) -> bool`**

Update a user's password hash. Returns `True` if a row was updated.

```python
success = update_user_password("550e8400-...", "<new_bcrypt_hash>")
```

**`update_user_public_key(user_id, new_public_key) -> bool`**

Replace a user's public key (e.g. after key rotation).

```python
success = update_user_public_key("550e8400-...", "<new_public_key_pem>")
```

---

### Delete

**`delete_user(user_id) -> bool`**

Delete a user by UUID. Cascades — also deletes all their sent/received messages.

```python
success = delete_user("550e8400-...")
```

---

## Messages

### Create

**`create_message(sender_id, recipient_id, content_ciphertext, nonce, digest, blockchain_tx_hash=None) -> dict`**

Insert a new encrypted message. Returns the full created row.

```python
msg = create_message(
    sender_id="550e8400-...",
    recipient_id="661f9511-...",
    content_ciphertext="<encrypted_payload>",
    nonce="<nonce_hex>",
    digest="<hmac_hex>",
)
```

---

### Read

**`get_message_by_id(message_id) -> dict | None`**

Fetch a single message by UUID.

```python
msg = get_message_by_id("772ga622-...")
```

**`get_messages_for_recipient(recipient_id) -> list[dict]`**

Fetch all messages sent to a user, ordered oldest first.

```python
inbox = get_messages_for_recipient("661f9511-...")
```

**`get_messages_by_sender(sender_id) -> list[dict]`**

Fetch all messages sent by a user, ordered oldest first.

```python
sent = get_messages_by_sender("550e8400-...")
```

**`get_conversation(user_a, user_b) -> list[dict]`**

Fetch the full message thread between two users, ordered oldest first.

```python
thread = get_conversation("550e8400-...", "661f9511-...")
```

---

### Update

**`update_blockchain_tx_hash(message_id, tx_hash) -> bool`**

Set the blockchain transaction hash once a message is anchored on-chain.

```python
success = update_blockchain_tx_hash("772ga622-...", "0xabc123...")
```

---

### Delete

**`delete_message(message_id) -> bool`**

Delete a single message by UUID.

```python
success = delete_message("772ga622-...")
```
